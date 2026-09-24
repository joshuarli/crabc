#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

/*
 * Buffering and flush-lifecycle transcript for the installed FILE engine.
 *
 * Every scenario runs in a fresh forked child whose standard output and
 * standard error share one target: a regular file, a pipe, or a
 * pseudo-terminal. The parent never touches its own stdio streams (the
 * transcript is written with raw write(2)), so each child starts with the
 * pristine permanent streams of a new process. Inside the child, raw
 * write(1, "[x]") markers, an atexit handler ("[A]") and an ELF destructor
 * ("[D]") interleave with stdio output, so the bytes the target receives
 * record the order in which the engine issued its writes.
 *
 * Pinned musl 1.2.6 behavior retained here:
 *   - src/stdio/stdout.c starts stdout with lbf '\n' and __stdout_write;
 *     src/stdio/__stdout_write.c probes TIOCGWINSZ on the first real write
 *     and, off a terminal and without setvbuf (F_SVB), sets lbf to -1;
 *   - src/stdio/fwrite.c::__fwritex writes through the last newline when
 *     lbf >= 0 and buffers the rest; __overflow.c flushes on lbf or a full
 *     buffer; stderr.c is unbuffered; puts.c is fputs plus putc('\n');
 *   - src/stdio/setvbuf.c changes only buf/buf_size/lbf and sets F_SVB,
 *     before or after I/O; setbuf/setbuffer/setlinebuf are its wrappers;
 *   - src/stdio/fflush.c with a null stream flushes stdout, stderr, then the
 *     open-file list newest first;
 *   - src/exit/exit.c runs atexit handlers, then ELF finalizers, then
 *     src/stdio/__stdio_exit.c, which writes pending output of the list
 *     (newest first), stdin, stdout, stderr, and seeks every read stream
 *     back over unread buffered input. A handler registered by a finalizer
 *     never runs. _Exit, quick_exit and abort write no buffered output;
 *     pthread_exit of the last thread is exit(0);
 *   - reading stdin never flushes stdout (__toread.c flushes only the stream
 *     being read);
 *   - src/stdio/fclose.c of a permanent stream closes its descriptor but
 *     keeps the FILE and its descriptor number.
 *
 * argv[1] is private scratch for this process and is removed before exit.
 * The runner supplies descriptor 3 opened on the /dev/ptmx multiplexer: the
 * dynamic cells execute in a chroot without devpts, so the probe unlocks
 * that master and opens its terminal through TIOCGPTPEER rather than a path.
 */

#define CHECK(x) do { if (!(x)) { char m[96]; int n = snprintf(m, sizeof m, "buffering:%d errno=%d\n", __LINE__, errno); \
    (void)!write(2, m, (size_t)n); _exit(1); } } while (0)

enum target { TARGET_FILE, TARGET_PIPE, TARGET_TTY };
enum finish { FINISH_RETURN, FINISH_EXIT, FINISH_QUICK, FINISH_QUICK_EXIT, FINISH_ABORT, FINISH_THREAD_EXIT };
enum input { INPUT_EMPTY, INPUT_PIPE, INPUT_FILE };

static const char *path;
static char input_path[4096];
static int master = -1;
static int in_child;
static int handler_stdio;
static int late_registration;

static void mark(const char *text) { (void)!write(1, text, strlen(text)); }

/* Report one integer through the shared target without using stdio. */
static void note(const char *label, long value)
{
    char text[64];
    int length = snprintf(text, sizeof text, "[%s=%ld]", label, value);
    (void)!write(2, text, (size_t)length);
}

static void on_late_handler(void) { mark("[L]"); }

static void on_exit_handler(void)
{
    mark("[A]");
    if (handler_stdio) fputs("atexit-stdio\n", stdout);
}

__attribute__((destructor)) static void on_destructor(void)
{
    if (!in_child) return;
    mark("[D]");
    if (handler_stdio) fputs("dtor-stdio\n", stdout);
    /* Registration after the atexit handlers ran is refused (musl's
     * finished_atexit), and exit never calls the handler. */
    if (late_registration) note("atexit", atexit(on_late_handler));
}

static void chunk(char byte, size_t count)
{
    static char bytes[512];
    CHECK(count <= sizeof bytes);
    memset(bytes, byte, count);
    CHECK(fwrite(bytes, 1, count, stdout) == count);
}

/* Scenarios. Each runs in a pristine child; finish selects its exit path. */
static void puts_split(void) { puts("\nok"); mark("[1]"); }
static void printf_literal(void) { printf("\nok\n"); mark("[1]"); printf("%s", "p\nq"); mark("[2]"); }
static void fputs_lines(void)
{
    fputs("x\ny\nz", stdout); mark("[1]");
    putchar('\n'); mark("[2]");
    fputc('w', stdout); putc('\n', stdout); mark("[3]");
    fputs("tail", stdout); mark("[4]");
}
static void first_write_by_flush(void) { fputs("f", stdout); mark("[1]"); fflush(stdout); mark("[2]"); fputs("g\nh", stdout); mark("[3]"); }
static void fwrite_overflow(void)
{
    for (int index = 0; index < 5; index++) { chunk((char)('a' + index), 300); mark("[+]"); }
}
static void putc_overflow(void)
{
    for (int index = 0; index < 1030; index++) putc('x', stdout);
    mark("[1]");
}
static void stderr_unbuffered(void)
{
    fputs("o1", stdout);
    fputs("e1", stderr); mark("[1]");
    fputc('e', stderr); mark("[2]");
    fprintf(stderr, "e%d\n", 2); mark("[3]");
    fwrite("e3", 1, 2, stderr); mark("[4]");
}
static void handlers_use_stdio(void) { handler_stdio = 1; fputs("main\n", stdout); mark("[1]"); }
static void setvbuf_unbuffered(void)
{
    CHECK(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    fputs("ab", stdout); mark("[1]"); putchar('c'); mark("[2]"); printf("d%d", 1); mark("[3]");
}
static char user_buffer[64];
static void setvbuf_line(void)
{
    CHECK(setvbuf(stdout, user_buffer, _IOLBF, sizeof user_buffer) == 0);
    fputs("l1\nl2", stdout); mark("[1]"); putchar('\n'); mark("[2]"); chunk('L', 60); mark("[3]");
}
static void setvbuf_full(void)
{
    CHECK(setvbuf(stdout, user_buffer, _IOFBF, 32) == 0);
    fputs("f1\n", stdout); mark("[1]"); chunk('F', 20); mark("[2]"); chunk('G', 10); mark("[3]");
}
static void setlinebuf_stdout(void) { setlinebuf(stdout); fputs("s1\ns2", stdout); mark("[1]"); }
static void setbuf_null(void) { setbuf(stdout, NULL); fputs("n1", stdout); mark("[1]"); putchar('n'); mark("[2]"); }
static void setbuf_user(void)
{
    static char buffer[BUFSIZ];
    setbuf(stdout, buffer); fputs("u1\nu2", stdout); mark("[1]");
}
static void setbuffer_small(void)
{
    setbuffer(stdout, user_buffer, 16);
    fputs("12345678", stdout); mark("[1]"); fputs("9", stdout); mark("[2]"); fputs("ab", stdout); mark("[3]");
}
static void setvbuf_after_io(void)
{
    fputs("x", stdout);
    CHECK(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    fputs("y", stdout); mark("[1]"); fflush(stdout); mark("[2]"); fputs("z", stdout); mark("[3]");
}
static void setvbuf_line_after_io(void)
{
    fputs("q", stdout);
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    fputs("r\ns", stdout); mark("[1]");
}
static void setvbuf_full_after_newline(void)
{
    fputs("k\n", stdout); mark("[1]");
    CHECK(setvbuf(stdout, NULL, _IOFBF, 0) == 0);
    fputs("m\nn", stdout); mark("[2]");
}
static char error_buffer[64];
static void stderr_buffered(void)
{
    CHECK(setvbuf(stderr, error_buffer, _IOFBF, sizeof error_buffer) == 0);
    fputs("E1\n", stderr); mark("[1]"); fputs("o", stdout); mark("[2]");
}
static FILE *older, *newer;
static void open_pair(void)
{
    older = fdopen(dup(1), "w"); newer = fdopen(dup(1), "w");
    CHECK(older && newer);
    CHECK(setvbuf(stderr, error_buffer, _IOFBF, sizeof error_buffer) == 0);
    fputs("s", stdout); fputs("1", older); fputs("2", newer); fputs("e", stderr);
}
static void flush_all_order(void) { open_pair(); mark("[1]"); CHECK(fflush(NULL) == 0); mark("[2]"); }
static void exit_order(void) { open_pair(); mark("[1]"); }
static void fdopen_terminal(void)
{
    FILE *stream = fdopen(dup(1), "w");
    CHECK(stream);
    fputs("t1\nt2", stream); mark("[1]");
}
static void fclose_stdout(void)
{
    fputs("c1", stdout); mark("[1]");
    note("fclose", fclose(stdout));
    note("fileno", fileno(stdout));
    /* The descriptor number survives in the permanent FILE: the lowest free
     * descriptor, reopened here, receives later stdout output as in musl. */
    note("dup", dup(2));
    fputs("after\n", stdout); mark("[2]");
}
static void stdin_no_flush(void)
{
    fputs("prompt", stdout);
    int c = getchar(); mark("[1]");
    note("getchar", c);
    char line[16];
    CHECK(fgets(line, sizeof line, stdin)); mark("[2]");
    fputs("line:", stdout); fputs(line, stdout); mark("[3]");
}
static void stdin_unread(void) { note("getchar", getchar()); note("getchar", getchar()); }
static void stdin_unread_pushback(void) { note("getchar", getchar()); note("ungetc", ungetc('Z', stdin)); }
static void stdin_flush(void) { note("getchar", getchar()); note("fflush", fflush(stdin)); }
static void stdin_read_all(void) { char buffer[32]; note("fread", (long)fread(buffer, 1, sizeof buffer, stdin)); }
static void list_unread(void)
{
    FILE *stream = fdopen(dup(0), "r");
    CHECK(stream);
    note("fgetc", fgetc(stream));
}

static void freopen_stdout(void)
{
    CHECK(freopen(path, "w", stdout) == stdout);
    fputs("a\nb", stdout); mark("[1]");
}
static void freopen_after_write(void)
{
    fputs("w\n", stdout); fflush(stdout);
    CHECK(freopen(path, "w", stdout) == stdout);
    fputs("a\nb", stdout); mark("[1]");
}
static void setvbuf_full_default(void)
{
    CHECK(setvbuf(stdout, NULL, _IOFBF, 0) == 0);
    fputs("a\nb", stdout); mark("[1]");
}
static void perror_buffered(void)
{
    CHECK(setvbuf(stderr, error_buffer, _IOFBF, sizeof error_buffer) == 0);
    errno = ENOENT; perror("p"); mark("[1]");
}
static void unlocked_bytes(void)
{
    putchar_unlocked('u'); putc_unlocked('\n', stdout); mark("[1]");
    fputc_unlocked('v', stdout); fwrite_unlocked("\nw", 1, 2, stdout); mark("[2]");
    fputs_unlocked("x\ny", stdout); mark("[3]");
}
static void wide_lines(void) { fputws(L"w1\nw2", stdout); mark("[1]"); fputwc(L'\n', stdout); mark("[2]"); }
static void fork_duplicates(void)
{
    fputs("f", stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) exit(0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    mark("[1]");
}
static void zero_writes(void)
{
    note("fwrite0", (long)fwrite("a\n", 0, 2, stdout)); note("fwrite00", (long)fwrite("a\n", 1, 0, stdout));
    fputs("", stdout); mark("[1]"); fputs("z\n", stdout); mark("[2]");
}
static void late_atexit(void) { late_registration = 1; fputs("late\n", stdout); mark("[1]"); }
static void pending_output(void) { fputs("pending\n", stdout); fputs("p", stdout); mark("[1]"); }

enum { ALL = 7, FILE_ONLY = 1 << TARGET_FILE };
struct scenario {
    const char *name;
    void (*run)(void);
    enum finish finish;
    enum input input;
    int targets;
};

static const struct scenario scenarios[] = {
    {"puts-split", puts_split, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"puts-split", puts_split, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"puts-split", puts_split, FINISH_QUICK, INPUT_EMPTY, ALL},
    {"printf-literal", printf_literal, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"fputs-lines", fputs_lines, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"first-write-by-flush", first_write_by_flush, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"fwrite-overflow", fwrite_overflow, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"putc-overflow", putc_overflow, FINISH_QUICK, INPUT_EMPTY, ALL},
    {"stderr-unbuffered", stderr_unbuffered, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"handlers-use-stdio", handlers_use_stdio, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"handlers-use-stdio", handlers_use_stdio, FINISH_QUICK, INPUT_EMPTY, ALL},
    {"setvbuf-unbuffered", setvbuf_unbuffered, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setvbuf-line", setvbuf_line, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setvbuf-full", setvbuf_full, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setlinebuf", setlinebuf_stdout, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setbuf-null", setbuf_null, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setbuf-user", setbuf_user, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"setbuffer-small", setbuffer_small, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setvbuf-after-io", setvbuf_after_io, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setvbuf-line-after-io", setvbuf_line_after_io, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"setvbuf-full-after-newline", setvbuf_full_after_newline, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"stderr-buffered", stderr_buffered, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"stderr-buffered", stderr_buffered, FINISH_QUICK, INPUT_EMPTY, ALL},
    {"flush-all-order", flush_all_order, FINISH_QUICK, INPUT_EMPTY, ALL},
    {"exit-order", exit_order, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"fdopen-terminal", fdopen_terminal, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"fclose-stdout", fclose_stdout, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"stdin-no-flush", stdin_no_flush, FINISH_RETURN, INPUT_PIPE, ALL},
    {"stdin-no-flush", stdin_no_flush, FINISH_RETURN, INPUT_FILE, FILE_ONLY},
    {"stdin-unread", stdin_unread, FINISH_RETURN, INPUT_FILE, FILE_ONLY},
    {"stdin-unread", stdin_unread, FINISH_EXIT, INPUT_FILE, FILE_ONLY},
    {"stdin-unread", stdin_unread, FINISH_QUICK, INPUT_FILE, FILE_ONLY},
    {"stdin-unread", stdin_unread, FINISH_EXIT, INPUT_PIPE, FILE_ONLY},
    {"stdin-unread-pushback", stdin_unread_pushback, FINISH_EXIT, INPUT_FILE, FILE_ONLY},
    {"stdin-flush", stdin_flush, FINISH_QUICK, INPUT_FILE, FILE_ONLY},
    {"stdin-read-all", stdin_read_all, FINISH_EXIT, INPUT_FILE, FILE_ONLY},
    {"list-unread", list_unread, FINISH_EXIT, INPUT_FILE, FILE_ONLY},
    {"list-unread", list_unread, FINISH_QUICK, INPUT_FILE, FILE_ONLY},
    {"freopen-stdout", freopen_stdout, FINISH_RETURN, INPUT_EMPTY, FILE_ONLY},
    {"freopen-after-write", freopen_after_write, FINISH_RETURN, INPUT_EMPTY, FILE_ONLY},
    {"setvbuf-full-default", setvbuf_full_default, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"perror-buffered", perror_buffered, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"unlocked-bytes", unlocked_bytes, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"wide-lines", wide_lines, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"fork-duplicates", fork_duplicates, FINISH_EXIT, INPUT_EMPTY, ALL},
    {"zero-writes", zero_writes, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"late-atexit", late_atexit, FINISH_RETURN, INPUT_EMPTY, ALL},
    {"pending-output", pending_output, FINISH_QUICK_EXIT, INPUT_EMPTY, ALL},
    {"pending-output", pending_output, FINISH_ABORT, INPUT_EMPTY, ALL},
    {"pending-output", pending_output, FINISH_THREAD_EXIT, INPUT_EMPTY, ALL},
};

static const char *const target_names[] = {"file", "pipe", "tty"};
static const char *const finish_names[] = {"return", "exit", "_Exit", "quick_exit", "abort", "pthread_exit"};
static const char *const input_names[] = {"", " stdin=pipe", " stdin=file"};
static const char input_bytes[] = "in\nsecond\n";

static char transcript[8192];
static size_t transcript_length;

static void emit(const char *text, size_t length)
{
    while (length) {
        ssize_t count = write(1, text, length);
        CHECK(count > 0);
        text += count; length -= (size_t)count;
    }
}

static void append(const char *text, size_t length)
{
    CHECK(transcript_length + length < sizeof transcript);
    memcpy(transcript + transcript_length, text, length);
    transcript_length += length;
}

/* Escape bytes; runs longer than eight collapse to {c*count}. */
static void escape(const unsigned char *bytes, size_t length)
{
    for (size_t index = 0; index < length;) {
        size_t run = 1;
        while (index + run < length && bytes[index + run] == bytes[index]) run++;
        char text[32];
        int count;
        if (run > 8) {
            count = snprintf(text, sizeof text, "{%c*%zu}", bytes[index], run);
            index += run;
        } else {
            unsigned char byte = bytes[index++];
            if (byte == '\n') count = snprintf(text, sizeof text, "\\n");
            else if (byte == '\r') count = snprintf(text, sizeof text, "\\r");
            else if (byte == '\\' || byte == '"') count = snprintf(text, sizeof text, "\\%c", byte);
            else if (byte < 0x20 || byte > 0x7e) count = snprintf(text, sizeof text, "\\x%02x", byte);
            else count = snprintf(text, sizeof text, "%c", byte);
        }
        append(text, (size_t)count);
    }
}

static void drain(int descriptor, int terminal)
{
    unsigned char bytes[4096];
    for (;;) {
        ssize_t count = read(descriptor, bytes, sizeof bytes);
        if (count > 0) { escape(bytes, (size_t)count); continue; }
        if (count < 0 && errno == EINTR) continue;
        /* A master reports EIO once its last terminal descriptor closed. */
        CHECK(count == 0 || (terminal && errno == EIO));
        return;
    }
}

static int open_input(enum input input, int *file)
{
    int ends[2];
    *file = -1;
    if (input == INPUT_FILE) {
        int descriptor = open(input_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        CHECK(descriptor >= 0 && !unlink(input_path));
        CHECK(write(descriptor, input_bytes, sizeof input_bytes - 1) == (ssize_t)(sizeof input_bytes - 1));
        CHECK(lseek(descriptor, 0, SEEK_SET) == 0);
        *file = descriptor;
        return descriptor;
    }
    CHECK(!pipe(ends));
    if (input == INPUT_PIPE)
        CHECK(write(ends[1], input_bytes, sizeof input_bytes - 1) == (ssize_t)(sizeof input_bytes - 1));
    CHECK(!close(ends[1]));
    return ends[0];
}

/* Returns 1 in the child, which then runs and finishes the scenario. */
static int launch(const struct scenario *scenario, enum target target)
{
    int input_file, input = open_input(scenario->input, &input_file);
    int output, reader = -1;
    if (target == TARGET_FILE) {
        output = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        CHECK(output >= 0);
    } else if (target == TARGET_PIPE) {
        int ends[2];
        CHECK(!pipe(ends));
        reader = ends[0]; output = ends[1];
    } else {
        output = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
        CHECK(output >= 0);
        reader = master;
    }
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(dup2(input, 0) == 0 && dup2(output, 1) == 1 && dup2(output, 2) == 2);
        CHECK(!close(input) && !close(output) && !close(master));
        if (reader >= 0 && reader != master) CHECK(!close(reader));
        in_child = 1;
        CHECK(!atexit(on_exit_handler));
        return 1;
    }
    CHECK(!close(output));
    if (input_file < 0) CHECK(!close(input));

    char header[160];
    int length = snprintf(header, sizeof header, "%s %s %s%s: \"", scenario->name, target_names[target],
                          finish_names[scenario->finish], input_names[scenario->input]);
    transcript_length = 0;
    append(header, (size_t)length);
    if (reader >= 0) drain(reader, target == TARGET_TTY);
    if (reader >= 0 && reader != master) CHECK(!close(reader));
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    if (target == TARGET_FILE) {
        int descriptor = open(path, O_RDONLY);
        CHECK(descriptor >= 0);
        drain(descriptor, 0);
        CHECK(!close(descriptor));
    }
    if (WIFSIGNALED(status)) length = snprintf(header, sizeof header, "\" signal=%d", WTERMSIG(status));
    else length = snprintf(header, sizeof header, "\" status=%d", WEXITSTATUS(status));
    append(header, (size_t)length);
    if (input_file >= 0) {
        length = snprintf(header, sizeof header, " stdin-offset=%ld", (long)lseek(input_file, 0, SEEK_CUR));
        append(header, (size_t)length);
        CHECK(!close(input_file));
    }
    append("\n", 1);
    emit(transcript, transcript_length);
    return 0;
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    path = argv[1];
    CHECK(snprintf(input_path, sizeof input_path, "%s.input", path) < (int)sizeof input_path);
    master = 3;
    CHECK(!unlockpt(master));
    alarm(60);
    for (size_t index = 0; index < sizeof scenarios / sizeof *scenarios; index++) {
        const struct scenario *scenario = &scenarios[index];
        for (int target = TARGET_FILE; target <= TARGET_TTY; target++) {
            if (!(scenario->targets & (1 << target))) continue;
            if (!launch(scenario, (enum target)target)) continue;
            scenario->run();
            if (scenario->finish == FINISH_EXIT) exit(7);
            if (scenario->finish == FINISH_QUICK) _Exit(7);
            if (scenario->finish == FINISH_QUICK_EXIT) quick_exit(7);
            if (scenario->finish == FINISH_ABORT) abort();
            if (scenario->finish == FINISH_THREAD_EXIT) pthread_exit(NULL);
            return 7;
        }
    }
    CHECK(!unlink(path));
    return 0;
}
