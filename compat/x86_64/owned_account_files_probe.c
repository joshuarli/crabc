/*
 * Installed account-file C ABI workload.
 *
 * Every execution is inside the runner's disposable chroot.  It never reads
 * a host account file.  The individual cases deliberately keep conventional
 * password hashes opaque: this only verifies the local-file ABI parser.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        dprintf(2, "account-files line %d errno %d\n", __LINE__, errno); \
        _exit(77); \
    } \
} while (0)

static void write_file(const char *path, const char *bytes, size_t length)
{
    int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(descriptor >= 0);
    CHECK(write(descriptor, bytes, length) == (ssize_t)length);
    CHECK(close(descriptor) == 0);
}

static void reset_account_files(void)
{
    (void)unlink("/etc/shells");
    (void)unlink("/etc/passwd");
    (void)unlink("/etc/shadow");
    (void)unlink("/etc/tcb/alpha/shadow");
    (void)rmdir("/etc/tcb/alpha/shadow");
    (void)rmdir("/etc/tcb/alpha");
    (void)unlink("/etc/tcb/beta/shadow");
    (void)rmdir("/etc/tcb/beta/shadow");
    (void)rmdir("/etc/tcb/beta");
    (void)unlink("/etc/tcb");
    (void)rmdir("/etc/tcb");
    CHECK(mkdir("/etc/tcb", 0700) == 0);
}

/* The base-red witness uses every requested public provider through installed
 * headers.  The later behavioral cases keep this same ordinary source file.
 */
static void symbol_smoke(void)
{
    struct spwd record = {0};
    struct spwd parsed = {0};
    struct spwd *result = (void *)1;
    char bytes[256] = {0};
    char user[L_cuserid] = {0};
    FILE *stream = fmemopen(bytes, sizeof bytes, "w+");
    CHECK(stream != NULL);
    setspent();
    endspent();
    CHECK(getspent() == NULL);
    CHECK(fgetspent(stream) == NULL);
    CHECK(getspnam("missing") == NULL);
    CHECK(getspnam_r("missing", &parsed, bytes, sizeof bytes, &result) == 0);
    CHECK(result == NULL);
    CHECK(putspent(&record, stream) == 0);
    CHECK(lckpwdf() == 0 && ulckpwdf() == 0);
    setusershell();
    (void)getusershell();
    endusershell();
    (void)cuserid(user);
    CHECK(fclose(stream) == 0);
}

static void setup_shadow(const char *records, size_t length)
{
    write_file("/etc/shadow", records, length);
}

static void check_shadow(const struct spwd *record, const char *name,
    const char *password, long changed, long minimum, long maximum, long warning,
    long inactive, long expires, unsigned long flag)
{
    CHECK(record != NULL);
    CHECK(!strcmp(record->sp_namp, name));
    CHECK(!strcmp(record->sp_pwdp, password));
    CHECK(record->sp_lstchg == changed && record->sp_min == minimum);
    CHECK(record->sp_max == maximum && record->sp_warn == warning);
    CHECK(record->sp_inact == inactive && record->sp_expire == expires);
    CHECK(record->sp_flag == flag);
}

static void shadow_fields(void)
{
    static const char records[] =
        "bad-no-colon\n"
        "badalpha:opaque:x:2:3:4:5:6:7\n"
        "badextra:opaque:1:2:3:4:5:6:7:8\n"
        "alpha:$opaque$:123:4:5:6:7:8:9\n"
        "empty:opaque:::::::\n"
        "flag:opaque:1:2:3:4:5:6:18446744073709551615\n"
        "tail:opaque:1:2:3:4:5:6:7";
    setup_shadow(records, sizeof records - 1);

    struct spwd record;
    struct spwd *result = (void *)1;
    char buffer[1024];
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "alpha", "$opaque$", 123, 4, 5, 6, 7, 8, 9);
    CHECK(record.sp_namp == buffer);
    CHECK(record.sp_pwdp == buffer + sizeof "alpha");

    errno = EDOM;
    result = (void *)1;
    CHECK(getspnam_r("empty", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "empty", "opaque", -1, -1, -1, -1, -1, -1,
        (unsigned long)-1);

    errno = EDOM;
    result = (void *)1;
    CHECK(getspnam_r("flag", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "flag", "opaque", 1, 2, 3, 4, 5, 6,
        (unsigned long)-1);

    errno = EDOM;
    result = (void *)1;
    CHECK(getspnam_r("badalpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == NULL && errno == EDOM);

    errno = EDOM;
    result = (void *)1;
    CHECK(getspnam_r("tail", &record, buffer, sizeof buffer, &result) == ERANGE);
    CHECK(result == NULL && errno == ERANGE);
}

static void unchanged_bytes(const char *bytes, size_t count, char expected)
{
    for (size_t index = 0; index < count; index++) {
        CHECK(bytes[index] == expected);
    }
}

static void shadow_early_errors(void)
{
    static const char record_text[] = "alpha:opaque:1:2:3:4:5:6:7\n";
    setup_shadow(record_text, sizeof record_text - 1);
    struct spwd record;
    struct spwd *result;
    char buffer[512];

    memset(&record, 0x5a, sizeof record);
    memset(buffer, 0x5a, sizeof buffer);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("", &record, buffer, sizeof buffer, &result) == EINVAL);
    CHECK(result == NULL && errno == EINVAL);
    unchanged_bytes(buffer, sizeof buffer, 0x5a);

    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r(".hidden", &record, buffer, sizeof buffer, &result) == EINVAL);
    CHECK(result == NULL && errno == EINVAL);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("a/b", &record, buffer, sizeof buffer, &result) == EINVAL);
    CHECK(result == NULL && errno == EINVAL);

    memset(buffer, 0x5a, sizeof buffer);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof "alpha" + 98, &result) == ERANGE);
    CHECK(result == NULL && errno == ERANGE);
    unchanged_bytes(buffer, sizeof buffer, 0x5a);

    char long_name[260];
    memset(long_name, 'a', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = 0;
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r(long_name, &record, buffer, sizeof buffer, &result) == EINVAL);
    CHECK(result == NULL && errno == EINVAL);

    CHECK(unlink("/etc/shadow") == 0);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == NULL && errno == ENOENT);
}

static void make_alpha_tcb_file(const char *text, size_t length)
{
    CHECK(mkdir("/etc/tcb/alpha", 0700) == 0);
    write_file("/etc/tcb/alpha/shadow", text, length);
}

static void clear_alpha_tcb(void)
{
    (void)unlink("/etc/tcb/alpha/shadow");
    (void)rmdir("/etc/tcb/alpha/shadow");
    (void)rmdir("/etc/tcb/alpha");
}

static void install_filter(int number, unsigned action)
{
    struct instruction { unsigned short code; unsigned char yes, no; unsigned value; };
    struct program { unsigned short count; struct instruction *instructions; };
    struct instruction instructions[] = {
        {0x20, 0, 0, 0}, {0x15, 0, 1, (unsigned)number},
        {0x06, 0, 0, action}, {0x06, 0, 0, 0x7fff0000},
    };
    struct program filter = {
        sizeof instructions / sizeof *instructions, instructions,
    };
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(syscall(SYS_seccomp, 1, 0, &filter) == 0);
}

static void shadow_tcb(void)
{
    static const char fallback[] = "alpha:fallback:1:2:3:4:5:6:7\n";
    static const char private_record[] = "alpha:tcb:8:9:10:11:12:13:14\n";
    setup_shadow(fallback, sizeof fallback - 1);
    struct spwd record;
    struct spwd *result;
    char buffer[512];

    errno = EDOM;
    result = NULL;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "alpha", "fallback", 1, 2, 3, 4, 5, 6, 7);

    make_alpha_tcb_file(private_record, sizeof private_record - 1);
    errno = EDOM;
    result = NULL;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "alpha", "tcb", 8, 9, 10, 11, 12, 13, 14);

    clear_alpha_tcb();
    CHECK(mkdir("/etc/tcb/alpha", 0700) == 0);
    CHECK(mkdir("/etc/tcb/alpha/shadow", 0700) == 0);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == EINVAL);
    CHECK(result == NULL && errno == EINVAL);
    clear_alpha_tcb();

    CHECK(mkdir("/etc/tcb/alpha", 0700) == 0);
    CHECK(symlink("/etc/shadow", "/etc/tcb/alpha/shadow") == 0);
    result = (void *)1;
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == ELOOP);
    CHECK(result == NULL && errno == ELOOP);
    clear_alpha_tcb();

    CHECK(rmdir("/etc/tcb") == 0);
    write_file("/etc/tcb", "x", 1);
    result = NULL;
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    check_shadow(&record, "alpha", "fallback", 1, 2, 3, 4, 5, 6, 7);
}

static void shadow_tcb_denied(void)
{
    static const char fallback[] = "alpha:fallback:1:2:3:4:5:6:7\n";
    setup_shadow(fallback, sizeof fallback - 1);
    struct spwd record;
    struct spwd *result = (void *)1;
    char buffer[512];
    install_filter(SYS_open, 0x00050000 | EACCES);
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == EACCES);
    CHECK(result == NULL && errno == EACCES);
}

static void shadow_global_and_fixed_buffer(void)
{
    static const char short_records[] =
        "one:one-hash:1:2:3:4:5:6:7\n"
        "two:two-hash:8:9:10:11:12:13:14\n";
    setup_shadow(short_records, sizeof short_records - 1);
    errno = EDOM;
    struct spwd *first = getspnam("one");
    CHECK(first != NULL && errno == EDOM);
    check_shadow(first, "one", "one-hash", 1, 2, 3, 4, 5, 6, 7);
    struct spwd *second = getspnam("two");
    CHECK(second == first && errno == EDOM);
    check_shadow(first, "two", "two-hash", 8, 9, 10, 11, 12, 13, 14);

    char long_record[400];
    size_t offset = 0;
    memcpy(long_record + offset, "long:", sizeof "long:" - 1);
    offset += sizeof "long:" - 1;
    memset(long_record + offset, 'p', 300);
    offset += 300;
    memcpy(long_record + offset, ":1:2:3:4:5:6:7\n", sizeof ":1:2:3:4:5:6:7\n" - 1);
    offset += sizeof ":1:2:3:4:5:6:7\n" - 1;
    setup_shadow(long_record, offset);
    errno = EDOM;
    CHECK(getspnam("long") == NULL && errno == ERANGE);
    struct spwd record;
    struct spwd *result = NULL;
    char buffer[512];
    errno = EDOM;
    CHECK(getspnam_r("long", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == &record && errno == EDOM);
    CHECK(record.sp_namp == buffer && record.sp_pwdp == buffer + sizeof "long");
}

static void shadow_stream_and_output(void)
{
    char input[] =
        "bad\n"
        "one:one-hash:1:2:3:4:5:6:7\n"
        "two:two-hash:8:9:10:11:12:13:14\n";
    FILE *stream = fmemopen(input, sizeof input - 1, "r");
    CHECK(stream != NULL);
    errno = EDOM;
    CHECK(fgetspent(stream) == NULL && errno == EDOM);
    struct spwd *first = fgetspent(stream);
    CHECK(first != NULL && errno == EDOM);
    check_shadow(first, "one", "one-hash", 1, 2, 3, 4, 5, 6, 7);
    struct spwd *second = fgetspent(stream);
    CHECK(second == first && errno == EDOM);
    check_shadow(first, "two", "two-hash", 8, 9, 10, 11, 12, 13, 14);
    CHECK(fgetspent(stream) == NULL && errno == EDOM);
    CHECK(fclose(stream) == 0);

    stream = fopen("/etc/putspent", "w+");
    CHECK(stream != NULL);
    struct spwd source = {
        .sp_lstchg = -1, .sp_min = -1, .sp_max = -1, .sp_warn = -1,
        .sp_inact = -1, .sp_expire = -1, .sp_flag = (unsigned long)-1,
    };
    CHECK(putspent(&source, stream) == 0 && fflush(stream) == 0);
    CHECK(fclose(stream) == 0);
    char output[256] = {0};
    stream = fopen("/etc/putspent", "r");
    CHECK(stream != NULL && fgets(output, sizeof output, stream) != NULL);
    CHECK(!strcmp(output, "::::::::\n"));
    CHECK(fclose(stream) == 0);
    source.sp_namp = "name";
    source.sp_pwdp = "opaque";
    source.sp_lstchg = 0;
    source.sp_min = 1;
    source.sp_max = 2;
    source.sp_warn = 3;
    source.sp_inact = 4;
    source.sp_expire = 5;
    source.sp_flag = 6;
    stream = fopen("/etc/putspent", "w");
    CHECK(stream != NULL);
    CHECK(putspent(&source, stream) == 0 && fflush(stream) == 0);
    CHECK(fclose(stream) == 0);
    char written[64] = {0};
    stream = fopen("/etc/putspent", "r");
    CHECK(stream != NULL && fgets(written, sizeof written, stream) != NULL);
    CHECK(!strcmp(written, "name:opaque:0:1:2:3:4:5:6\n"));
    CHECK(fclose(stream) == 0);

    stream = fopen("/etc/putspent", "r");
    CHECK(stream != NULL && close(fileno(stream)) == 0);
    errno = 0;
    CHECK(fgetspent(stream) == NULL && ferror(stream) && errno == EBADF);
    CHECK(fclose(stream) == -1);

    stream = fopen("/etc/putspent", "w");
    CHECK(stream != NULL && setvbuf(stream, NULL, _IONBF, 0) == 0);
    CHECK(close(fileno(stream)) == 0);
    errno = 0;
    CHECK(putspent(&source, stream) == -1 && ferror(stream) && errno == EBADF);
    CHECK(fclose(stream) == -1);
}

static int descriptor_count(void)
{
    int count = 0;
    for (int descriptor = 3; descriptor < 64; descriptor++) {
        if (fcntl(descriptor, F_GETFD) >= 0) {
            count++;
        }
    }
    return count;
}

static void shadow_read_error(void)
{
    static const char record_text[] = "alpha:opaque:1:2:3:4:5:6:7\n";
    setup_shadow(record_text, sizeof record_text - 1);
    int before = descriptor_count();
    struct spwd record;
    struct spwd *result = (void *)1;
    char buffer[512];
    install_filter(SYS_read, 0x00050000 | EIO);
    errno = EDOM;
    CHECK(getspnam_r("alpha", &record, buffer, sizeof buffer, &result) == 0);
    CHECK(result == NULL && errno == EDOM);
    CHECK(descriptor_count() == before);
}

static void *shadow_worker(void *argument)
{
    const char *name = argument;
    for (unsigned iteration = 0; iteration < 100; iteration++) {
        struct spwd record;
        struct spwd *result = NULL;
        char buffer[512];
        CHECK(getspnam_r(name, &record, buffer, sizeof buffer, &result) == 0);
        CHECK(result == &record && !strcmp(record.sp_namp, name));
        CHECK(record.sp_namp >= buffer && record.sp_namp < buffer + sizeof buffer);
        CHECK(record.sp_pwdp >= buffer && record.sp_pwdp < buffer + sizeof buffer);
    }
    return NULL;
}

static void shadow_workers(void)
{
    static const char records[] =
        "alpha:one:1:2:3:4:5:6:7\n"
        "beta:two:8:9:10:11:12:13:14\n";
    setup_shadow(records, sizeof records - 1);
    pthread_t first, second;
    CHECK(pthread_create(&first, NULL, shadow_worker, "alpha") == 0);
    CHECK(pthread_create(&second, NULL, shadow_worker, "beta") == 0);
    CHECK(pthread_join(first, NULL) == 0 && pthread_join(second, NULL) == 0);
}

static volatile int cancellation_started;

static void *pending_shadow_lookup(void *unused)
{
    (void)unused;
    /* getspnam_r reaches its cancellation-point TCB open before installing
     * the fgets cleanup handler. A self-pending request must retire there;
     * the parent checks the process descriptor table after join. */
    cancellation_started = 1;
    CHECK(pthread_cancel(pthread_self()) == 0);
    struct spwd record;
    struct spwd *result = NULL;
    char buffer[512];
    (void)getspnam_r("alpha", &record, buffer, sizeof buffer, &result);
    _exit(78);
}

static void shadow_cancellation(void)
{
    static const char record_text[] = "alpha:opaque:1:2:3:4:5:6:7\n";
    setup_shadow(record_text, sizeof record_text - 1);
    int before = descriptor_count();
    pthread_t thread;
    void *result;
    CHECK(pthread_create(&thread, NULL, pending_shadow_lookup, NULL) == 0);
    CHECK(pthread_join(thread, &result) == 0);
    CHECK(result == PTHREAD_CANCELED && cancellation_started);
    CHECK(descriptor_count() == before);
}

static void source_noops(void)
{
    setspent();
    endspent();
    CHECK(getspent() == NULL);
    CHECK(lckpwdf() == 0 && lckpwdf() == 0);
    CHECK(ulckpwdf() == 0 && ulckpwdf() == 0);
}

static void usershell(void)
{
    static const char shells[] =
        "# comment\n"
        "\n"
        "/bin/one\n"
        " # preserved\n"
        "/bin/two\n"
        "last";
    write_file("/etc/shells", shells, sizeof shells - 1);
    endusershell();
    CHECK(!strcmp(getusershell(), "/bin/one"));
    setusershell();
    CHECK(!strcmp(getusershell(), " # preserved"));
    CHECK(!strcmp(getusershell(), "/bin/two"));
    CHECK(!strcmp(getusershell(), "last"));
    CHECK(getusershell() == NULL);
    setusershell();
    CHECK(getusershell() == NULL);
    endusershell();
    CHECK(!strcmp(getusershell(), "/bin/one"));
    endusershell();

    CHECK(unlink("/etc/shells") == 0);
    CHECK(!strcmp(getusershell(), "/bin/sh"));
    CHECK(!strcmp(getusershell(), "/bin/csh"));
    CHECK(getusershell() == NULL);
    endusershell();
}

static void cuserid_case(void)
{
    static const char records[] =
        "root:x:0:0:Root:/root:/bin/sh\n"
        "alice:x:1001:1001:Alice:/alice:/bin/sh\n";
    write_file("/etc/passwd", records, sizeof records - 1);
    CHECK(setresuid((uid_t)-1, 1001, (uid_t)-1) == 0);
    CHECK(geteuid() == 1001);
    char supplied[L_cuserid + 1];
    memset(supplied, 0x5a, sizeof supplied);
    CHECK(cuserid(supplied) == supplied && !strcmp(supplied, "alice"));
    CHECK(supplied[L_cuserid] == 0x5a);
    char *shared = cuserid(NULL);
    CHECK(shared != NULL && !strcmp(shared, "alice"));
    CHECK(cuserid(NULL) == shared);
    CHECK(cuserid(supplied) == supplied && !strcmp(shared, "alice"));
    CHECK(setresuid((uid_t)-1, 0, (uid_t)-1) == 0);
    CHECK(geteuid() == 0);

    static const char long_record[] = "abcdefghijklmnopqrst:x:0:0:L:/l:/s\n";
    write_file("/etc/passwd", long_record, sizeof long_record - 1);
    memset(supplied, 0x5a, sizeof supplied);
    CHECK(cuserid(supplied) == supplied && supplied[0] == 0);
    CHECK(cuserid(NULL) == NULL);

    static const char missing_record[] = "other:x:44:44:O:/o:/s\n";
    write_file("/etc/passwd", missing_record, sizeof missing_record - 1);
    memset(supplied, 0x5a, sizeof supplied);
    CHECK(cuserid(supplied) == supplied && supplied[0] == 0);
    CHECK(cuserid(NULL) == NULL);
}

static void setup_identity_files(void)
{
    static const char passwd_records[] =
        "broken\n"
        "bad:x:-1:2:Bad:/bad:/bin/no\n"
        "alice:x:4294967297:2:Alice:/home/alice:/bin/sh\n"
        "alice:x:1:2:Later:/later:/bin/no\n"
        "bob:x:2:4294967298:Bob:/home/bob:/bin/ksh\n"
        "tail:x:3:3:Tail:/tail:/bin/z";
    static const char group_records[] =
        "broken\n"
        "bad:x:+1:nobody\n"
        "team:x:4294967297:alice,bob\n"
        "team:x:1:later\n"
        "lab:x:2:bob,,alice,\n"
        "tail:x:3:last";
    write_file("/etc/passwd", passwd_records, sizeof passwd_records - 1);
    write_file("/etc/group", group_records, sizeof group_records - 1);
}

static void check_identity_fields(void)
{
    struct passwd passwd_record;
    struct passwd *passwd_result = (void *)1;
    struct group group_record;
    struct group *group_result = (void *)1;
    char passwd_buffer[512];
    char group_buffer[512];

    setup_identity_files();
    memset(passwd_buffer, 0x5a, sizeof passwd_buffer);
    memset(group_buffer, 0x5a, sizeof group_buffer);
    CHECK(getpwnam_r("alice", &passwd_record, passwd_buffer, 8,
        &passwd_result) == ERANGE);
    CHECK(passwd_result == NULL && passwd_buffer[0] == 0x5a);
    CHECK(getgrnam_r("team", &group_record, group_buffer, 8,
        &group_result) == ERANGE);
    CHECK(group_result == NULL && group_buffer[0] == 0x5a);

    CHECK(getpwnam_r("alice", &passwd_record, passwd_buffer,
        sizeof passwd_buffer, &passwd_result) == 0);
    CHECK(passwd_result == &passwd_record && passwd_record.pw_uid == 1);
    CHECK(passwd_record.pw_gid == 2);
    CHECK(!strcmp(passwd_record.pw_gecos, "Alice"));
    CHECK(!strcmp(passwd_record.pw_dir, "/home/alice"));
    CHECK(!strcmp(passwd_record.pw_shell, "/bin/sh"));
    CHECK(getpwuid_r(2, &passwd_record, passwd_buffer, sizeof passwd_buffer,
        &passwd_result) == 0);
    CHECK(passwd_result == &passwd_record && !strcmp(passwd_record.pw_name, "bob"));
    CHECK(passwd_record.pw_gid == 2);
    CHECK(getpwnam_r("tail", &passwd_record, passwd_buffer,
        sizeof passwd_buffer, &passwd_result) == 0);
    CHECK(passwd_result == &passwd_record && !strcmp(passwd_record.pw_shell, "/bin/"));

    CHECK(getgrnam_r("team", &group_record, group_buffer,
        sizeof group_buffer, &group_result) == 0);
    CHECK(group_result == &group_record && group_record.gr_gid == 1);
    CHECK(!strcmp(group_record.gr_mem[0], "alice"));
    CHECK(!strcmp(group_record.gr_mem[1], "bob") && group_record.gr_mem[2] == NULL);
    CHECK(getgrgid_r(2, &group_record, group_buffer,
        sizeof group_buffer, &group_result) == 0);
    CHECK(group_result == &group_record && !strcmp(group_record.gr_name, "lab"));
    CHECK(!strcmp(group_record.gr_mem[0], "bob"));
    CHECK(!strcmp(group_record.gr_mem[1], ",alice"));
    CHECK(!strcmp(group_record.gr_mem[2], "") && group_record.gr_mem[3] == NULL);
    CHECK(getgrnam_r("tail", &group_record, group_buffer,
        sizeof group_buffer, &group_result) == 0);
    CHECK(group_result == &group_record && !strcmp(group_record.gr_mem[0], "las"));
}

static pthread_barrier_t identity_ready;
static pthread_barrier_t identity_release;

static void wait_identity_barrier(pthread_barrier_t *barrier)
{
    int result = pthread_barrier_wait(barrier);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *identity_worker(void *argument)
{
    const char *name = argument;
    struct passwd passwd_record;
    struct passwd *passwd_result = (void *)1;
    struct group group_record;
    struct group *group_result = (void *)1;
    char passwd_buffer[512];
    char group_buffer[512];
    const char *group_name = !strcmp(name, "alice") ? "team" : "lab";

    CHECK(getpwnam_r(name, &passwd_record, passwd_buffer,
        sizeof passwd_buffer, &passwd_result) == 0);
    CHECK(getgrnam_r(group_name, &group_record, group_buffer,
        sizeof group_buffer, &group_result) == 0);
    CHECK(passwd_result == &passwd_record && group_result == &group_record);
    CHECK((uintptr_t)passwd_record.pw_name >= (uintptr_t)passwd_buffer);
    CHECK((uintptr_t)passwd_record.pw_name < (uintptr_t)(passwd_buffer + sizeof passwd_buffer));
    CHECK((uintptr_t)group_record.gr_mem >= (uintptr_t)group_buffer);
    CHECK((uintptr_t)group_record.gr_mem < (uintptr_t)(group_buffer + sizeof group_buffer));
    wait_identity_barrier(&identity_ready);
    wait_identity_barrier(&identity_release);
    CHECK(!strcmp(passwd_record.pw_name, name));
    CHECK(!strcmp(group_record.gr_name, group_name));
    CHECK(!strcmp(group_record.gr_mem[0], !strcmp(name, "alice") ? "alice" : "bob"));
    return NULL;
}

static void check_identity_lifetime(void)
{
    pthread_t first, second;
    struct passwd *shared_passwd;
    struct group *shared_group;
    FILE *passwd_stream;
    FILE *group_stream;
    int iteration;

    setup_identity_files();
    setpwent();
    setgrent();
    shared_passwd = getpwent();
    shared_group = getgrent();
    CHECK(shared_passwd != NULL && !strcmp(shared_passwd->pw_name, "alice"));
    CHECK(shared_group != NULL && !strcmp(shared_group->gr_name, "team"));
    CHECK(getpwnam("bob") == shared_passwd);
    CHECK(getgrnam("lab") == shared_group);
    CHECK(!strcmp(getpwent()->pw_gecos, "Later"));
    CHECK(!strcmp(getgrent()->gr_mem[0], "later"));
    CHECK(!strcmp(getpwent()->pw_name, "bob"));
    CHECK(!strcmp(getgrent()->gr_name, "lab"));

    passwd_stream = fopen("/etc/passwd", "r");
    group_stream = fopen("/etc/group", "r");
    CHECK(passwd_stream != NULL && group_stream != NULL);
    CHECK(fgetpwent(passwd_stream) != shared_passwd);
    CHECK(fgetgrent(group_stream) != shared_group);
    CHECK(!strcmp(getpwent()->pw_name, "tail"));
    CHECK(!strcmp(getgrent()->gr_name, "tail"));
    CHECK(fclose(passwd_stream) == 0 && fclose(group_stream) == 0);
    endpwent();
    endgrent();

    CHECK(pthread_barrier_init(&identity_ready, NULL, 3) == 0);
    CHECK(pthread_barrier_init(&identity_release, NULL, 3) == 0);
    CHECK(pthread_create(&first, NULL, identity_worker, "alice") == 0);
    CHECK(pthread_create(&second, NULL, identity_worker, "bob") == 0);
    wait_identity_barrier(&identity_ready);
    for (iteration = 0; iteration < 32; iteration++) {
        CHECK(!strcmp(getpwnam(iteration & 1 ? "alice" : "bob")->pw_name,
            iteration & 1 ? "alice" : "bob"));
        CHECK(!strcmp(getgrnam(iteration & 1 ? "team" : "lab")->gr_name,
            iteration & 1 ? "team" : "lab"));
    }
    wait_identity_barrier(&identity_release);
    CHECK(pthread_join(first, NULL) == 0 && pthread_join(second, NULL) == 0);
    CHECK(pthread_barrier_destroy(&identity_ready) == 0);
    CHECK(pthread_barrier_destroy(&identity_release) == 0);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    reset_account_files();
    if (!strcmp(argv[1], "symbols")) symbol_smoke();
    else if (!strcmp(argv[1], "fields")) shadow_fields();
    else if (!strcmp(argv[1], "early")) shadow_early_errors();
    else if (!strcmp(argv[1], "tcb")) shadow_tcb();
    else if (!strcmp(argv[1], "tcb-denied")) shadow_tcb_denied();
    else if (!strcmp(argv[1], "global")) shadow_global_and_fixed_buffer();
    else if (!strcmp(argv[1], "stream")) shadow_stream_and_output();
    else if (!strcmp(argv[1], "read-error")) shadow_read_error();
    else if (!strcmp(argv[1], "workers")) shadow_workers();
    else if (!strcmp(argv[1], "cancellation")) shadow_cancellation();
    else if (!strcmp(argv[1], "noops")) source_noops();
    else if (!strcmp(argv[1], "usershell")) usershell();
    else if (!strcmp(argv[1], "cuserid")) cuserid_case();
    else if (!strcmp(argv[1], "identity-fields")) check_identity_fields();
    else if (!strcmp(argv[1], "identity-lifetime")) check_identity_lifetime();
    else CHECK(!"unknown account-file scenario");
    puts("owned account files scenario passed");
    return 0;
}
