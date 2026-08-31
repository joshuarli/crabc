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

_Static_assert(SYS_close == 3 && SYS_getpid == 39 && SYS_mq_open == 240 &&
    SYS_mq_unlink == 241 && SYS_mq_getsetattr == 245,
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
    return raw3(SYS_mq_getsetattr, descriptor, 0, (long)(void *)attributes) == 0;
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
    int descriptor = -1;
    int result = 0;

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
    if (!query_attributes(descriptor, &observed_attributes) ||
        !attributes_match(&observed_attributes, 0)) {
        result = 12;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    clear_attributes(&old_attributes);
    new_attributes.mq_flags = O_NONBLOCK;
    errno = ERANGE;
    if (mq_setattr(descriptor, &new_attributes, &old_attributes) != 0 ||
        errno != ERANGE || !attributes_match(&old_attributes, 0) ||
        !query_attributes(descriptor, &observed_attributes) ||
        !attributes_match(&observed_attributes, O_NONBLOCK)) {
        result = 13;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    errno = EDOM;
    if (mq_setattr(descriptor, &new_attributes, (struct mq_attr *)0) != 0 ||
        errno != EDOM || !query_attributes(descriptor, &observed_attributes) ||
        !attributes_match(&observed_attributes, 0)) {
        result = 14;
        goto cleanup;
    }

    clear_attributes(&new_attributes);
    new_attributes.mq_flags = 1;
    errno = E2BIG;
    if (mq_setattr(descriptor, &new_attributes, &old_attributes) != -1 ||
        errno != EINVAL || !query_attributes(descriptor, &observed_attributes) ||
        !attributes_match(&observed_attributes, 0)) {
        result = 15;
        goto cleanup;
    }

    if (close_descriptor(descriptor) != 0) {
        result = 16;
        goto cleanup;
    }
    descriptor = -1;
    clear_attributes(&new_attributes);
    errno = EFBIG;
    if (mq_setattr(-1, &new_attributes, &old_attributes) != -1 || errno != EBADF) {
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
