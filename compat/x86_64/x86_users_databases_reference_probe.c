/* Pinned-musl/raw Linux/x86-64 conventional local-account snapshot reference. */

/*
 * This fixture deliberately models only ordinary local files. Each raw or
 * musl child creates a private `etc/passwd` and `etc/group` below a fresh
 * /tmp directory, reads a complete immutable byte snapshot, and removes that
 * private tree before exiting. It never opens or changes the host's /etc.
 *
 * The musl arm uses only openat/read/close; the raw arm issues the matching
 * Linux syscalls. In particular, this is not evidence for getpwnam,
 * getgrnam, NSS, provider modules, static account results, or C account
 * database enumeration.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

_Static_assert(sizeof(int) == 4 && sizeof(pid_t) == 4,
               "x86 int and pid_t width");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8,
               "x86 LP64 byte-count widths");
_Static_assert(SYS_read == 0 && SYS_close == 3 && SYS_openat == 257,
               "x86 local-snapshot syscall numbers");
_Static_assert(AT_FDCWD == -100, "x86 current-directory token");
_Static_assert(O_RDONLY == 0 && O_CLOEXEC == 0x00080000,
               "x86 read-only close-on-exec flags");

enum reader_kind {
    READER_RAW,
    READER_MUSL,
};

enum database_kind {
    DATABASE_PASSWD,
    DATABASE_GROUP,
};

enum {
    READ_CHUNK_BYTES = 17,
    SNAPSHOT_CAPACITY = 512,
};

static const unsigned char passwd_snapshot[] =
    "# private local passwd fixture\n"
    "\n"
    "first:x:1000:100:First User:/home/first:/bin/sh\n"
    "second:!:1001:100:Second User:/srv/second:/usr/bin/false\n"
    "first:x:1000:200:Later Duplicate:/home/later:/bin/bash\n";

static const unsigned char group_snapshot[] =
    "# private local group fixture\n"
    "\n"
    "staff:x:100:first,second\n"
    "staff:x:100:later\n"
    "empty:x:201:\n";

static const unsigned char first_user_record[] =
    "first:x:1000:100:First User:/home/first:/bin/sh";
static const unsigned char later_user_record[] =
    "first:x:1000:200:Later Duplicate:/home/later:/bin/bash";
static const unsigned char first_group_record[] = "staff:x:100:first,second";
static const unsigned char later_group_record[] = "staff:x:100:later";

static const unsigned char malformed_passwd_fields[] =
    "broken:x:1000:100:only:five\n";
static const unsigned char malformed_passwd_identifier[] =
    "broken:x:4294967296:100::/:/bin/sh\n";
static const unsigned char malformed_group_members[] =
    "staff:x:100:member,,other\n";

struct snapshot {
    unsigned char bytes[SNAPSHOT_CAPACITY];
    size_t length;
};

static int raw_openat(int directory, const char *path, int flags, mode_t mode)
{
    return (int)syscall(SYS_openat, directory, path, flags, mode);
}

static ssize_t raw_read(int descriptor, void *buffer, size_t length)
{
    return (ssize_t)syscall(SYS_read, descriptor, buffer, length);
}

static int raw_close(int descriptor)
{
    return (int)syscall(SYS_close, descriptor);
}

static int snapshot_open(enum reader_kind reader, const char *path)
{
    if (reader == READER_RAW)
        return raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    return openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
}

static ssize_t snapshot_read(enum reader_kind reader, int descriptor,
                             void *buffer, size_t length)
{
    if (reader == READER_RAW)
        return raw_read(descriptor, buffer, length);
    return read(descriptor, buffer, length);
}

static int snapshot_close(enum reader_kind reader, int descriptor)
{
    if (reader == READER_RAW)
        return raw_close(descriptor);
    return close(descriptor);
}

static int write_all(int descriptor, const unsigned char *bytes, size_t length)
{
    while (length != 0) {
        ssize_t written = write(descriptor, bytes, length);

        if (written > 0) {
            bytes += written;
            length -= (size_t)written;
            continue;
        }
        if (written == -1 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int create_fixture_file(const char *path, const unsigned char *bytes,
                               size_t length)
{
    int descriptor = openat(AT_FDCWD, path,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int result = 1;

    if (descriptor < 0) return 0;
    if (!write_all(descriptor, bytes, length)) result = 0;
    if (close(descriptor) != 0) result = 0;
    return result;
}

static int read_snapshot(enum reader_kind reader, const char *path,
                         struct snapshot *snapshot)
{
    int descriptor = snapshot_open(reader, path);
    int result = 1;
    int reached_eof = 0;

    if (descriptor < 0) return 0;
    snapshot->length = 0;
    while (snapshot->length < sizeof(snapshot->bytes)) {
        size_t remaining = sizeof(snapshot->bytes) - snapshot->length;
        size_t request = remaining < READ_CHUNK_BYTES ? remaining : READ_CHUNK_BYTES;
        ssize_t read_count = snapshot_read(reader, descriptor,
                                           snapshot->bytes + snapshot->length,
                                           request);

        if (read_count > 0) {
            snapshot->length += (size_t)read_count;
            continue;
        }
        if (read_count == 0) {
            reached_eof = 1;
            break;
        }
        if (errno == EINTR) continue;
        result = 0;
        break;
    }
    if (!reached_eof) result = 0;
    if (snapshot_close(reader, descriptor) != 0) result = 0;
    return result;
}

static int expect_missing(enum reader_kind reader, const char *path)
{
    int descriptor;

    errno = 0;
    descriptor = snapshot_open(reader, path);
    if (descriptor >= 0) {
        (void)snapshot_close(reader, descriptor);
        return 0;
    }
    return errno == ENOENT;
}

static int next_line(const unsigned char *input, size_t input_length,
                     size_t *offset, const unsigned char **line,
                     size_t *line_length)
{
    size_t start;
    size_t end;

    if (*offset >= input_length) return 0;
    start = *offset;
    end = start;
    while (end < input_length && input[end] != '\n') ++end;
    *offset = end < input_length ? end + 1 : end;
    if (end > start && input[end - 1] == '\r') --end;
    *line = input + start;
    *line_length = end - start;
    return 1;
}

static unsigned field_count(const unsigned char *line, size_t line_length)
{
    unsigned count = 1;
    size_t index;

    for (index = 0; index < line_length; ++index) {
        if (line[index] == ':') ++count;
    }
    return count;
}

static int field_at(const unsigned char *line, size_t line_length,
                    unsigned wanted, const unsigned char **field,
                    size_t *field_length)
{
    unsigned current = 0;
    size_t start = 0;
    size_t index;

    for (index = 0; index <= line_length; ++index) {
        if (index != line_length && line[index] != ':') continue;
        if (current == wanted) {
            *field = line + start;
            *field_length = index - start;
            return 1;
        }
        ++current;
        start = index + 1;
    }
    return 0;
}

static int decimal_u32(const unsigned char *field, size_t field_length)
{
    uint32_t value = 0;
    size_t index;

    if (field_length == 0) return 0;
    for (index = 0; index < field_length; ++index) {
        uint32_t digit;

        if (field[index] < '0' || field[index] > '9') return 0;
        digit = (uint32_t)(field[index] - '0');
        if (value > (UINT32_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    return 1;
}

static int member_list(const unsigned char *field, size_t field_length)
{
    int needs_member = 0;
    size_t index;

    if (field_length == 0) return 1;
    for (index = 0; index < field_length; ++index) {
        if (field[index] == ',') {
            if (index == 0 || needs_member) return 0;
            needs_member = 1;
        } else {
            needs_member = 0;
        }
    }
    return !needs_member;
}

static int valid_record(const unsigned char *line, size_t line_length,
                        enum database_kind database)
{
    const unsigned char *field;
    size_t field_length;
    unsigned expected_fields = database == DATABASE_PASSWD ? 7 : 4;

    if (line_length == 0 || line[0] == '#') return 1;
    if (memchr(line, '\0', line_length) != NULL ||
        field_count(line, line_length) != expected_fields ||
        !field_at(line, line_length, 0, &field, &field_length) ||
        field_length == 0) {
        return 0;
    }
    if (database == DATABASE_PASSWD) {
        if (!field_at(line, line_length, 2, &field, &field_length) ||
            !decimal_u32(field, field_length) ||
            !field_at(line, line_length, 3, &field, &field_length) ||
            !decimal_u32(field, field_length)) {
            return 0;
        }
    } else {
        if (!field_at(line, line_length, 2, &field, &field_length) ||
            !decimal_u32(field, field_length) ||
            !field_at(line, line_length, 3, &field, &field_length) ||
            !member_list(field, field_length)) {
            return 0;
        }
    }
    return 1;
}

static int validate_snapshot(const unsigned char *input, size_t input_length,
                             enum database_kind database,
                             unsigned *record_count)
{
    const unsigned char *line;
    size_t line_length;
    size_t offset = 0;
    unsigned records = 0;

    while (next_line(input, input_length, &offset, &line, &line_length)) {
        if (!valid_record(line, line_length, database)) return 0;
        if (line_length != 0 && line[0] != '#') ++records;
    }
    *record_count = records;
    return 1;
}

static int nth_record_matches_field(const unsigned char *input,
                                    size_t input_length, unsigned field_index,
                                    const char *value, unsigned occurrence,
                                    const unsigned char *expected,
                                    size_t expected_length)
{
    const unsigned char *line;
    const unsigned char *field;
    size_t line_length;
    size_t field_length;
    size_t offset = 0;
    size_t value_length = strlen(value);
    unsigned seen = 0;

    while (next_line(input, input_length, &offset, &line, &line_length)) {
        if (line_length == 0 || line[0] == '#' ||
            !field_at(line, line_length, field_index, &field, &field_length) ||
            field_length != value_length || memcmp(field, value, value_length) != 0) {
            continue;
        }
        ++seen;
        if (seen != occurrence) continue;
        return line_length == expected_length &&
               memcmp(line, expected, expected_length) == 0;
    }
    return 0;
}

static int snapshot_semantics(const struct snapshot *snapshot,
                              enum database_kind database)
{
    unsigned records;

    if (database == DATABASE_PASSWD) {
        if (snapshot->length != sizeof(passwd_snapshot) - 1 ||
            memcmp(snapshot->bytes, passwd_snapshot, snapshot->length) != 0 ||
            !validate_snapshot(snapshot->bytes, snapshot->length, database, &records) ||
            records != 3 ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 0,
                                      "first", 1, first_user_record,
                                      sizeof(first_user_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 0,
                                      "first", 2, later_user_record,
                                      sizeof(later_user_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 2,
                                      "1000", 1, first_user_record,
                                      sizeof(first_user_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 2,
                                      "1000", 2, later_user_record,
                                      sizeof(later_user_record) - 1)) {
            return 0;
        }
    } else {
        if (snapshot->length != sizeof(group_snapshot) - 1 ||
            memcmp(snapshot->bytes, group_snapshot, snapshot->length) != 0 ||
            !validate_snapshot(snapshot->bytes, snapshot->length, database, &records) ||
            records != 3 ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 0,
                                      "staff", 1, first_group_record,
                                      sizeof(first_group_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 0,
                                      "staff", 2, later_group_record,
                                      sizeof(later_group_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 2,
                                      "100", 1, first_group_record,
                                      sizeof(first_group_record) - 1) ||
            !nth_record_matches_field(snapshot->bytes, snapshot->length, 2,
                                      "100", 2, later_group_record,
                                      sizeof(later_group_record) - 1)) {
            return 0;
        }
    }
    return 1;
}

static int malformed_snapshots_reject(void)
{
    unsigned records;

    return !validate_snapshot(malformed_passwd_fields,
                              sizeof(malformed_passwd_fields) - 1,
                              DATABASE_PASSWD, &records) &&
           !validate_snapshot(malformed_passwd_identifier,
                              sizeof(malformed_passwd_identifier) - 1,
                              DATABASE_PASSWD, &records) &&
           !validate_snapshot(malformed_group_members,
                              sizeof(malformed_group_members) - 1,
                              DATABASE_GROUP, &records);
}

static int build_path(char *destination, size_t capacity, const char *root,
                      const char *leaf)
{
    int written = snprintf(destination, capacity, "%s/%s", root, leaf);

    return written >= 0 && (size_t)written < capacity;
}

static int run_snapshot_child(enum reader_kind reader)
{
    char root[] = "/tmp/crabc-x86-users-databases-XXXXXX";
    char etc_path[PATH_MAX];
    char passwd_path[PATH_MAX];
    char group_path[PATH_MAX];
    char missing_path[PATH_MAX];
    struct snapshot passwd;
    struct snapshot group;
    int made_root = 0;
    int made_etc = 0;
    int status = 0;

    if (mkdtemp(root) == NULL) return 10;
    made_root = 1;
    if (!build_path(etc_path, sizeof(etc_path), root, "etc") ||
        !build_path(passwd_path, sizeof(passwd_path), root, "etc/passwd") ||
        !build_path(group_path, sizeof(group_path), root, "etc/group") ||
        !build_path(missing_path, sizeof(missing_path), root, "etc/missing")) {
        status = 11;
        goto cleanup;
    }
    if (mkdir(etc_path, 0700) != 0) {
        status = 12;
        goto cleanup;
    }
    made_etc = 1;
    if (!create_fixture_file(passwd_path, passwd_snapshot,
                             sizeof(passwd_snapshot) - 1)) {
        status = 13;
        goto cleanup;
    }
    if (!create_fixture_file(group_path, group_snapshot,
                             sizeof(group_snapshot) - 1)) {
        status = 14;
        goto cleanup;
    }

    if (!expect_missing(reader, missing_path)) {
        status = 15;
        goto cleanup;
    }
    if (!read_snapshot(reader, passwd_path, &passwd) ||
        !read_snapshot(reader, group_path, &group)) {
        status = 16;
        goto cleanup;
    }
    if (!snapshot_semantics(&passwd, DATABASE_PASSWD) ||
        !snapshot_semantics(&group, DATABASE_GROUP) ||
        !malformed_snapshots_reject()) {
        status = 17;
        goto cleanup;
    }

cleanup:
    if (made_etc && unlink(passwd_path) != 0 && errno != ENOENT && status == 0)
        status = 20;
    if (made_etc && unlink(group_path) != 0 && errno != ENOENT && status == 0)
        status = 21;
    if (made_etc && rmdir(etc_path) != 0 && status == 0) status = 22;
    if (made_root && rmdir(root) != 0 && status == 0) status = 23;
    return status;
}

static int child_succeeds(enum reader_kind reader)
{
    pid_t child = fork();
    int status;

    if (child < 0) return 0;
    if (child == 0) _exit(run_snapshot_child(reader));
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 0;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int main(void)
{
    if (!child_succeeds(READER_RAW) || !child_succeeds(READER_MUSL)) return 1;

    puts("users-databases=openat=257 read=0 close=3 raw+musl=success order=preserved first=preserved malformed=rejected child-contained");
    return 0;
}
