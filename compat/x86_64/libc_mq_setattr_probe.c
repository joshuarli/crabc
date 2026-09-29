/* Static crabc-libc x86-64 freestanding mq_setattr fixture. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    queue_mode = 0600,
    queue_maximum_messages = 2,
    queue_message_size = 32,
    queue_flags = O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
};

_Static_assert(SYS_write == 1 && SYS_close == 3 && SYS_getpid == 39 &&
    SYS_mq_open == 240 && SYS_mq_unlink == 241 && SYS_mq_timedsend == 242 &&
    SYS_mq_getsetattr == 245,
    "x86 mq_setattr fixture syscalls");
_Static_assert(sizeof(mqd_t) == sizeof(int), "x86 mqd_t is an int descriptor");
_Static_assert(sizeof(struct mq_attr) == 64 && _Alignof(struct mq_attr) == 8,
    "x86 mq_attr layout");
_Static_assert(offsetof(struct mq_attr, mq_flags) == 0 &&
    offsetof(struct mq_attr, mq_maxmsg) == 8 &&
    offsetof(struct mq_attr, mq_msgsize) == 16 &&
    offsetof(struct mq_attr, mq_curmsgs) == 24,
    "x86 mq_attr field offsets");
_Static_assert(SYS_mq_getsetattr == 245 && O_NONBLOCK == 0x800,
    "x86 mq_setattr ABI values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mq_setattr),
    int (*)(mqd_t, const struct mq_attr *, struct mq_attr *)),
    "mq_setattr declaration");

static long raw0(long number)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw1(long number, long argument_one)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one) : "rcx", "r11", "memory");
    return result;
}

static long raw3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
    return result;
}

static long raw4(long number, long argument_one, long argument_two,
    long argument_three, long argument_four)
{
    long result;
    register long register_four __asm__("r10") = argument_four;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four)
        : "rcx", "r11", "memory");
    return result;
}

static long raw5(long number, long argument_one, long argument_two,
    long argument_three, long argument_four, long argument_five)
{
    long result;
    register long register_four __asm__("r10") = argument_four;
    register long register_five __asm__("r8") = argument_five;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(register_four), "r"(register_five)
        : "rcx", "r11", "memory");
    return result;
}

static size_t append_text(char *buffer, size_t length, const char *text)
{
    while (*text)
        buffer[length++] = *text++;
    return length;
}

static size_t append_number(char *buffer, size_t length, long value)
{
    char digits[24];
    size_t count = 0;
    unsigned long magnitude;

    if (value < 0) {
        buffer[length++] = '-';
        magnitude = (unsigned long)(-(value + 1)) + 1;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[count++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    while (count)
        buffer[length++] = digits[--count];
    return length;
}

/* Each record describes observable status, errno, and the four kernel fields. */
static int trace_case(const char *name, long status, int error,
    const struct mq_attr *old, const struct mq_attr *current)
{
    char buffer[192];
    size_t length = append_text(buffer, 0, name);
    const struct mq_attr *records[2] = { old, current };
    size_t index;

    buffer[length++] = ' ';
    length = append_number(buffer, length, status);
    buffer[length++] = ' ';
    length = append_number(buffer, length, error);
    for (index = 0; index < 2; ++index) {
        const struct mq_attr *record = records[index];
        buffer[length++] = ' ';
        length = append_number(buffer, length, record->mq_flags);
        buffer[length++] = ' ';
        length = append_number(buffer, length, record->mq_maxmsg);
        buffer[length++] = ' ';
        length = append_number(buffer, length, record->mq_msgsize);
        buffer[length++] = ' ';
        length = append_number(buffer, length, record->mq_curmsgs);
    }
    buffer[length++] = '\n';
    return raw3(SYS_write, 1, (long)(void *)buffer, length) == (long)length;
}

static int queue_name(char *name, size_t capacity, long process_id)
{
    static const char prefix[] = "crabc-x86-mq-setattr-";
    char digits[20];
    size_t index = 0;
    size_t prefix_length = 0;
    size_t digit_count = 0;
    unsigned long identifier = (unsigned long)process_id;

    while (prefix[prefix_length] != '\0') {
        if (index + 1 >= capacity)
            return -1;
        name[index++] = prefix[prefix_length++];
    }
    do {
        if (digit_count == sizeof(digits))
            return -1;
        digits[digit_count++] = (char)('0' + identifier % 10);
        identifier /= 10;
    } while (identifier);
    while (digit_count) {
        if (index + 1 >= capacity)
            return -1;
        name[index++] = digits[--digit_count];
    }
    name[index] = '\0';
    return 0;
}

static void clear_attributes(struct mq_attr *attributes)
{
    size_t index;
    unsigned char *bytes = (unsigned char *)attributes;

    for (index = 0; index < sizeof(*attributes); ++index)
        bytes[index] = 0;
}

static int attributes_match(const struct mq_attr *attributes, long flags)
{
    return attributes->mq_flags == flags &&
        attributes->mq_maxmsg == queue_maximum_messages &&
        attributes->mq_msgsize == queue_message_size &&
        attributes->mq_curmsgs == 0;
}

static int query_attributes(int descriptor, struct mq_attr *attributes)
{
    clear_attributes(attributes);
#ifndef CRABC_MQ_SETATTR_FREESTANDING
    return mq_getattr(descriptor, attributes) == 0;
#else
    return raw3(SYS_mq_getsetattr, descriptor, 0, (long)(void *)attributes) == 0;
#endif
}

static int close_descriptor(int descriptor)
{
    return descriptor >= 0 && raw1(SYS_close, descriptor) < 0 ? -1 : 0;
}

int crabc_x86_64_mq_setattr_probe(void)
{
    char name[64];
    struct mq_attr creation_attributes;
    struct mq_attr new_attributes;
    struct mq_attr old_attributes;
    struct mq_attr observed_attributes;
    const char message = 'x';
    int descriptor = -1;
    int result = 0;
    int status;
    int error;

    if (queue_name(name, sizeof(name), raw0(SYS_getpid)) != 0)
        return 10;
    clear_attributes(&creation_attributes);
    creation_attributes.mq_maxmsg = queue_maximum_messages;
    creation_attributes.mq_msgsize = queue_message_size;
    descriptor = (int)raw4(SYS_mq_open, (long)(void *)name, queue_flags,
        queue_mode, (long)(void *)&creation_attributes);
    if (descriptor < 0) {
        result = 11;
        goto cleanup;
    }
    clear_attributes(&old_attributes);
    errno = ERANGE;
    status = query_attributes(descriptor, &observed_attributes) ? 0 : -1;
    error = errno;
    if (!trace_case("get-empty", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != ERANGE ||
        !attributes_match(&observed_attributes, 0)) {
        result = 12;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    clear_attributes(&old_attributes);
    new_attributes.mq_flags = O_NONBLOCK;
    new_attributes.mq_maxmsg = 99;
    new_attributes.mq_msgsize = 99;
    new_attributes.mq_curmsgs = 99;
    errno = ERANGE;
    status = mq_setattr(descriptor, &new_attributes, &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("set-nonblock", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != ERANGE ||
        !attributes_match(&old_attributes, 0) ||
        !attributes_match(&observed_attributes, O_NONBLOCK)) {
        result = 13;
        goto cleanup;
    }

    clear_attributes(&old_attributes);
    errno = EDOM;
    status = mq_setattr(descriptor, &new_attributes, &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("set-again", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != EDOM ||
        !attributes_match(&old_attributes, O_NONBLOCK) ||
        !attributes_match(&observed_attributes, O_NONBLOCK)) {
        result = 18;
        goto cleanup;
    }

    if (raw5(SYS_mq_timedsend, descriptor, (long)(void *)&message,
            1, 3, 0) != 0) {
        result = 19;
        goto cleanup;
    }
    clear_attributes(&old_attributes);
    errno = EDOM;
    status = query_attributes(descriptor, &observed_attributes) ? 0 : -1;
    error = errno;
    if (!trace_case("get-one-message", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != EDOM ||
        observed_attributes.mq_flags != O_NONBLOCK ||
        observed_attributes.mq_curmsgs != 1) {
        result = 20;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    clear_attributes(&old_attributes);
    errno = EDOM;
    status = mq_setattr(descriptor, &new_attributes, &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("clear-with-message", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != EDOM ||
        old_attributes.mq_flags != O_NONBLOCK ||
        old_attributes.mq_curmsgs != 1 ||
        observed_attributes.mq_flags != 0 ||
        observed_attributes.mq_curmsgs != 1) {
        result = 14;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    clear_attributes(&old_attributes);
    new_attributes.mq_flags = 1;
    old_attributes.mq_flags = 12345;
    errno = E2BIG;
    status = mq_setattr(descriptor, &new_attributes, &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("invalid-flags", status, error, &old_attributes,
            &observed_attributes) || status != -1 || error != EINVAL ||
        old_attributes.mq_flags != 12345 ||
        observed_attributes.mq_flags != 0 ||
        observed_attributes.mq_curmsgs != 1) {
        result = 15;
        goto cleanup;
    }

    clear_attributes(&old_attributes);
    errno = ERANGE;
    status = mq_setattr(descriptor, (const struct mq_attr *)0,
        &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("null-new-query", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != ERANGE ||
        old_attributes.mq_flags != 0 || old_attributes.mq_curmsgs != 1) {
        result = 21;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    new_attributes.mq_flags = O_NONBLOCK;
    clear_attributes(&old_attributes);
    errno = EDOM;
    status = mq_setattr(descriptor, &new_attributes, (struct mq_attr *)0);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("null-old", status, error, &old_attributes,
            &observed_attributes) || status != 0 || error != EDOM ||
        observed_attributes.mq_flags != O_NONBLOCK ||
        observed_attributes.mq_curmsgs != 1) {
        result = 22;
        goto cleanup;
    }

    new_attributes.mq_flags = 0;
    old_attributes.mq_flags = 12345;
    errno = EDOM;
    status = mq_setattr(descriptor, (const struct mq_attr *)(uintptr_t)1,
        &old_attributes);
    error = errno;
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("bad-new-pointer", status, error, &old_attributes,
            &observed_attributes) || status != -1 || error != EFAULT ||
        old_attributes.mq_flags != 12345 ||
        observed_attributes.mq_flags != O_NONBLOCK) {
        result = 23;
        goto cleanup;
    }

    errno = EDOM;
    status = mq_setattr(descriptor, &new_attributes,
        (struct mq_attr *)(uintptr_t)1);
    error = errno;
    clear_attributes(&old_attributes);
    if (!query_attributes(descriptor, &observed_attributes) ||
        !trace_case("bad-old-pointer", status, error, &old_attributes,
            &observed_attributes) || status != -1 || error != EFAULT ||
        observed_attributes.mq_flags != 0 ||
        observed_attributes.mq_curmsgs != 1) {
        result = 24;
        goto cleanup;
    }

    if (close_descriptor(descriptor) != 0) {
        result = 16;
        goto cleanup;
    }
    descriptor = -1;
    clear_attributes(&new_attributes);
    clear_attributes(&old_attributes);
    old_attributes.mq_flags = 12345;
    errno = EFBIG;
    status = mq_setattr(-1, &new_attributes, &old_attributes);
    error = errno;
    clear_attributes(&observed_attributes);
    if (!trace_case("bad-descriptor", status, error, &old_attributes,
            &observed_attributes) || status != -1 || error != EBADF ||
        old_attributes.mq_flags != 12345) {
        result = 17;
        goto cleanup;
    }

cleanup:
    (void)close_descriptor(descriptor);
    (void)raw1(SYS_mq_unlink, (long)(void *)name);
    return result;
}

#ifndef CRABC_MQ_SETATTR_FREESTANDING
int main(void)
{
    return crabc_x86_64_mq_setattr_probe();
}
#endif
