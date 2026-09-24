/* Owned static product startup-publication consumer.
 *
 * One ordinary C program observes what process startup publishes before and
 * after application constructors: the argument and environment vectors, the
 * kernel auxiliary vector that follows them, the musl program-name globals,
 * and the ELF main-image coordinates named by `AT_PHDR`/`AT_ENTRY`. It then
 * re-executes itself through `/proc/self/exe` with a replacement vector and
 * environment so the same publication is observed for a second kernel image.
 *
 * The transcript contains only facts that must be identical for a pinned-musl
 * static executable and both owned static link modes: no addresses, times, or
 * random bytes. The runner supplies the exact argument and environment
 * strings, so their bytes are part of the compared transcript.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "owned static startup publication requires native Linux/x86-64 LP64"
#endif

#include <elf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
/* Musl publishes these globals from argv[0]; the GNU spellings in <errno.h>
 * are weak same-address aliases of them. */
extern char *__progname;
extern char *__progname_full;
/* Linker-defined main-image and CRT entry anchors. Hidden visibility keeps
 * both static modes free of GOT-mediated dynamic relocations. */
extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));
extern char _start[] __attribute__((visibility("hidden")));

static const char startup_name[] = "CRABC_STATIC_STARTUP";

static struct {
    int ran;
    int errno_clear;
    int environment_published;
    int program_names_published;
    int page_size_published;
    char *program_name;
} constructor_view;

__attribute__((constructor))
static void observe_constructor(void)
{
    const char *value;

    /* Musl calls constructors without arguments; publication must already
     * be complete through the process globals alone. */
    constructor_view.ran = 1;
    constructor_view.errno_clear = errno == 0;
    value = environ != NULL ? getenv(startup_name) : NULL;
    constructor_view.environment_published = value != NULL &&
        (strcmp(value, "published") == 0 || strcmp(value, "child") == 0);
    constructor_view.program_names_published = program_invocation_name != NULL &&
        program_invocation_short_name != NULL &&
        __progname_full == program_invocation_name &&
        __progname == program_invocation_short_name;
    constructor_view.page_size_published =
        getauxval(AT_PAGESZ) == (unsigned long)sysconf(_SC_PAGESIZE);
    constructor_view.program_name = program_invocation_name;
}

static void emit(const char *format, ...) __attribute__((format(printf, 1, 2)));

static void emit(const char *format, ...)
{
    char line[512];
    va_list arguments;
    int length;

    va_start(arguments, format);
    length = vsnprintf(line, sizeof line, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof line)
        _exit(90);
    for (size_t written = 0; written < (size_t)length;) {
        ssize_t count = write(1, line + written, (size_t)length - written);
        if (count <= 0)
            _exit(91);
        written += (size_t)count;
    }
}

/* Render caller-supplied bytes without letting spaces or non-ASCII bytes
 * change the line structure of the compared transcript. */
static const char *escaped(const char *text, char *buffer, size_t capacity)
{
    static const char digits[] = "0123456789abcdef";
    size_t length = 0;

    for (const unsigned char *cursor = (const unsigned char *)text; *cursor != 0; ++cursor) {
        if (length + 5 >= capacity)
            _exit(92);
        if (*cursor > 0x20 && *cursor < 0x7f && *cursor != '\\') {
            buffer[length++] = (char)*cursor;
        } else {
            buffer[length++] = '\\';
            buffer[length++] = 'x';
            buffer[length++] = digits[*cursor >> 4];
            buffer[length++] = digits[*cursor & 0xf];
        }
    }
    buffer[length] = 0;
    return buffer;
}

static const char *basename_of(const char *path)
{
    const char *base = path;

    for (const char *cursor = path; *cursor != 0; ++cursor) {
        if (*cursor == '/')
            base = cursor + 1;
    }
    return base;
}

static const unsigned long *initial_auxv(char **envp)
{
    char **cursor = envp;

    while (*cursor != NULL)
        ++cursor;
    return (const unsigned long *)(cursor + 1);
}

/* Return the first raw value for `tag`; musl's lookup is first-match. */
static int raw_auxv(const unsigned long *auxv, unsigned long tag, unsigned long *value)
{
    for (size_t index = 0; index < 4096; ++index) {
        if (auxv[index * 2] == AT_NULL)
            return 0;
        if (auxv[index * 2] == tag) {
            *value = auxv[index * 2 + 1];
            return 1;
        }
    }
    _exit(93);
}

static void observe_auxv(const unsigned long *auxv)
{
    static const struct {
        unsigned long tag;
        const char *name;
    } tags[] = {
        { AT_PHDR, "AT_PHDR" }, { AT_PHENT, "AT_PHENT" }, { AT_PHNUM, "AT_PHNUM" },
        { AT_PAGESZ, "AT_PAGESZ" }, { AT_ENTRY, "AT_ENTRY" }, { AT_UID, "AT_UID" },
        { AT_EUID, "AT_EUID" }, { AT_GID, "AT_GID" }, { AT_EGID, "AT_EGID" },
        { AT_SECURE, "AT_SECURE" }, { AT_RANDOM, "AT_RANDOM" }, { AT_EXECFN, "AT_EXECFN" },
    };
    size_t entries = 0;
    int consistent = 1;

    /* Every raw pair, including tags this program does not name, must be
     * visible unchanged through getauxval without disturbing errno. */
    for (; auxv[entries * 2] != AT_NULL; ++entries) {
        unsigned long tag = auxv[entries * 2];
        unsigned long first = 0;

        if (entries == 4096)
            _exit(94);
        if (!raw_auxv(auxv, tag, &first))
            _exit(95);
        errno = EDOM;
        if (getauxval(tag) != first || errno != EDOM)
            consistent = 0;
    }
    emit("auxv consistent=%d terminated=%d\n", consistent, entries > 0);
    for (size_t index = 0; index < sizeof tags / sizeof tags[0]; ++index) {
        unsigned long value = 0;
        emit("auxv %s present=%d\n", tags[index].name, raw_auxv(auxv, tags[index].tag, &value));
    }

    errno = 0;
    unsigned long missing = getauxval(0x7ff0);
    emit("auxv absent value=%lu errno=%s\n", missing, errno == ENOENT ? "ENOENT" : "other");
    errno = 0;
    missing = getauxval(AT_NULL);
    emit("auxv AT_NULL value=%lu errno=%s\n", missing, errno == ENOENT ? "ENOENT" : "other");
}

static void observe_image(void)
{
    const unsigned char *image = (const unsigned char *)&__ehdr_start;
    unsigned long phdr = getauxval(AT_PHDR);
    const unsigned char *random = (const unsigned char *)getauxval(AT_RANDOM);
    int random_nonzero = 0;

    if (memcmp(__ehdr_start.e_ident, ELFMAG, SELFMAG) != 0)
        _exit(96);
    for (unsigned index = 0; random != NULL && index < 16; ++index)
        random_nonzero |= random[index] != 0;
    emit("image phdr=%d phnum=%d phent=%d entry=%d random=%d\n",
        phdr == (uintptr_t)(image + __ehdr_start.e_phoff),
        getauxval(AT_PHNUM) == __ehdr_start.e_phnum,
        getauxval(AT_PHENT) == sizeof(Elf64_Phdr) && __ehdr_start.e_phentsize == sizeof(Elf64_Phdr),
        getauxval(AT_ENTRY) == (uintptr_t)_start,
        random_nonzero);
    emit("identity uid=%d euid=%d gid=%d egid=%d secure=%lu\n",
        getauxval(AT_UID) == (unsigned long)getuid(),
        getauxval(AT_EUID) == (unsigned long)geteuid(),
        getauxval(AT_GID) == (unsigned long)getgid(),
        getauxval(AT_EGID) == (unsigned long)getegid(),
        getauxval(AT_SECURE));
    emit("page size auxv=sysconf:%d getpagesize:%d\n",
        getauxval(AT_PAGESZ) == (unsigned long)sysconf(_SC_PAGESIZE),
        getauxval(AT_PAGESZ) == (unsigned long)getpagesize());
}

static void observe_vectors(const char *role, int argc, char **argv, char **envp)
{
    char buffer[256];
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    size_t environment_count = 0;

    emit("%s constructor ran=%d errno=%d environ=%d names=%d pagesz=%d same-name=%d\n", role,
        constructor_view.ran, constructor_view.errno_clear,
        constructor_view.environment_published, constructor_view.program_names_published,
        constructor_view.page_size_published, constructor_view.program_name == argv[0]);
    emit("%s main errno=%d argc=%d terminated=%d\n", role, errno == 0, argc, argv[argc] == NULL);
    for (int index = 1; index < argc; ++index)
        emit("%s argv[%d]=%s\n", role, index, escaped(argv[index], buffer, sizeof buffer));
    emit("%s argv0 execfn=%s\n", role,
        execfn != NULL && strcmp(execfn, argv[0]) == 0 ? "argv0" :
        execfn != NULL && strcmp(execfn, "/proc/self/exe") == 0 ? "proc-self-exe" : "other");
    emit("%s program full=%d short=%d aliases=%d\n", role,
        program_invocation_name == argv[0],
        program_invocation_short_name == basename_of(argv[0]),
        (void *)&program_invocation_name == (void *)&__progname_full &&
        (void *)&program_invocation_short_name == (void *)&__progname);
    emit("%s environ main=%d adjacent=%d\n", role, environ == envp, envp == argv + argc + 1);
    for (char **cursor = envp; *cursor != NULL; ++cursor)
        emit("%s envp[%zu]=%s\n", role, environment_count++, escaped(*cursor, buffer, sizeof buffer));
    emit("%s getenv startup=%s empty=%d missing=%d secure=%d\n", role,
        escaped(getenv(startup_name) ? getenv(startup_name) : "(null)", buffer, sizeof buffer),
        getenv("CRABC_EMPTY") != NULL && getenv("CRABC_EMPTY")[0] == 0,
        getenv("CRABC_MISSING") == NULL,
        secure_getenv(startup_name) == getenv(startup_name));
}

static int relaunch(void)
{
    char *const child_argv[] = { "relaunched-startup", "--child", "after exec", NULL };
    char *const child_envp[] = { "CRABC_STATIC_STARTUP=child", "CRABC_EMPTY=", NULL };
    int status = 0;
    pid_t child = fork();

    if (child < 0)
        return 80;
    if (child == 0) {
        execve("/proc/self/exe", child_argv, child_envp);
        _exit(81);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
        return 82;
    return WEXITSTATUS(status);
}

int main(int argc, char **argv, char **envp)
{
    const unsigned long *auxv = initial_auxv(envp);
    int child_status;

    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        observe_vectors("child", argc, argv, envp);
        observe_auxv(auxv);
        return 0;
    }
    observe_vectors("parent", argc, argv, envp);
    observe_auxv(auxv);
    observe_image();
    child_status = relaunch();
    emit("relaunch status=%d\n", child_status);
    return child_status == 0 ? 0 : 1;
}
