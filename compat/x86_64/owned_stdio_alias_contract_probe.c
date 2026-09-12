/*
 * Exercise musl 1.2.6's same-address stdio aliases and their locking shape.
 *
 * The callbacks synchronously create and join a contender while the active
 * operation is inside its backend callback.  That gives ftrylockfile an
 * unambiguous observation of the enclosing operation's lock: there is no
 * timing loop or probabilistic scheduling assumption.  Musl aliases fread,
 * fwrite, fgetws and fputws to their locking bodies; the byte and wide-char
 * unlocked aliases retain their caller-held-lock contract.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <wchar.h>

extern wint_t __fgetwc_unlocked(FILE *);
extern wint_t __fputwc_unlocked(wint_t, FILE *);

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "stdio-alias-contract:%d errno=%d\n", __LINE__, errno); \
        return 1; \
    } \
} while (0)

#define SAME_ADDRESS(first, second) ((uintptr_t)(first) == (uintptr_t)(second))

struct lock_round {
    FILE *stream;
    int expected_locked;
    int observed_locked;
    int callback_count;
    int failed;
    const char *input;
    size_t input_offset;
};

static void *contender(void *opaque)
{
    struct lock_round *round = opaque;
    int acquired = ftrylockfile(round->stream) == 0;

    round->observed_locked = !acquired;
    if (acquired)
        funlockfile(round->stream);
    return NULL;
}

static int observe_enclosing_lock(struct lock_round *round)
{
    pthread_t thread;

    if (pthread_create(&thread, NULL, contender, round) != 0)
        return 0;
    if (pthread_join(thread, NULL) != 0)
        return 0;
    ++round->callback_count;
    return round->observed_locked == round->expected_locked;
}

static ssize_t read_cookie(void *opaque, char *destination, size_t count)
{
    struct lock_round *round = opaque;
    size_t available;

    if (!observe_enclosing_lock(round)) {
        round->failed = 1;
        errno = EIO;
        return -1;
    }
    available = 2 - round->input_offset;
    if (available > count)
        available = count;
    if (available != 0) {
        for (size_t index = 0; index != available; ++index)
            destination[index] = round->input[round->input_offset + index];
        round->input_offset += available;
    }
    return (ssize_t)available;
}

static ssize_t write_cookie(void *opaque, const char *source, size_t count)
{
    struct lock_round *round = opaque;

    (void)source;
    if (!observe_enclosing_lock(round)) {
        round->failed = 1;
        errno = EIO;
        return -1;
    }
    return (ssize_t)count;
}

static FILE *open_read_round(struct lock_round *round, int expected_locked)
{
    cookie_io_functions_t functions = { .read = read_cookie };
    FILE *stream;

    *round = (struct lock_round){
        .expected_locked = expected_locked,
        .input = "x\n",
    };
    stream = fopencookie(round, "r", functions);
    if (stream == NULL)
        return NULL;
    round->stream = stream;
    if (setvbuf(stream, NULL, _IONBF, 0) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static FILE *open_write_round(struct lock_round *round, int expected_locked)
{
    cookie_io_functions_t functions = { .write = write_cookie };
    FILE *stream;

    *round = (struct lock_round){ .expected_locked = expected_locked };
    stream = fopencookie(round, "w", functions);
    if (stream == NULL)
        return NULL;
    round->stream = stream;
    if (setvbuf(stream, NULL, _IONBF, 0) != 0) {
        fclose(stream);
        return NULL;
    }
    return stream;
}

static int check_alias_addresses(void)
{
    CHECK(SAME_ADDRESS(fgetc_unlocked, getc_unlocked));
    CHECK(SAME_ADDRESS(fputc_unlocked, putc_unlocked));
    CHECK(SAME_ADDRESS(fread_unlocked, fread));
    CHECK(SAME_ADDRESS(fwrite_unlocked, fwrite));
    CHECK(SAME_ADDRESS(fgetwc_unlocked, __fgetwc_unlocked));
    CHECK(SAME_ADDRESS(getwc_unlocked, __fgetwc_unlocked));
    CHECK(SAME_ADDRESS(fputwc_unlocked, __fputwc_unlocked));
    CHECK(SAME_ADDRESS(putwc_unlocked, __fputwc_unlocked));
    CHECK(SAME_ADDRESS(fgetws_unlocked, fgetws));
    CHECK(SAME_ADDRESS(fputws_unlocked, fputws));
    CHECK(SAME_ADDRESS(getwchar_unlocked, getwchar));
    CHECK(SAME_ADDRESS(putwchar_unlocked, putwchar));
    return 0;
}

static int check_read_locking(void)
{
    struct lock_round round;
    FILE *stream;
    char byte;
    wchar_t wide[4];

    stream = open_read_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fgetc_unlocked(stream) == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fread_unlocked(&byte, 1, 1, stream) == 1 && byte == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fgetwc_unlocked(stream) == L'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_read_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fgetws_unlocked(wide, 4, stream) == wide && wide[0] == L'x'
          && wide[1] == L'\n' && wide[2] == L'\0');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);
    return 0;
}

static int check_write_locking(void)
{
    struct lock_round round;
    FILE *stream;

    stream = open_write_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fputc_unlocked('x', stream) == 'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fwrite_unlocked("x", 1, 1, stream) == 1);
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 0);
    CHECK(stream != NULL);
    CHECK(fputwc_unlocked(L'x', stream) == L'x');
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);

    stream = open_write_round(&round, 1);
    CHECK(stream != NULL);
    CHECK(fputws_unlocked(L"x", stream) >= 0);
    CHECK(!round.failed && round.callback_count != 0 && fclose(stream) == 0);
    return 0;
}

int main(void)
{
    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != NULL);
    CHECK(check_alias_addresses() == 0);
    CHECK(check_read_locking() == 0);
    CHECK(check_write_locking() == 0);
    puts("owned-stdio-alias-contract-ok");
    return 0;
}
