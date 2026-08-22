#include <errno.h>
#include <iconv.h>
#include <stdio.h>

static int report(const char *name, size_t result, char *input,
                  char *input_base, size_t input_left, char *output,
                  char *output_base, size_t output_left) {
    fprintf(stderr,
            "%s: result=%zu errno=%d input_offset=%zu input_left=%zu "
            "output_offset=%zu output_left=%zu\n",
            name, result, errno, (size_t)(input - input_base), input_left,
            (size_t)(output - output_base), output_left);
    return 1;
}

static iconv_t open_utf8(void) {
    iconv_t cd = iconv_open("UTF-8", "UTF-8");
    if (cd == (iconv_t)-1) {
        fprintf(stderr, "iconv_open UTF-8/UTF-8 failed: errno=%d\n", errno);
    }
    return cd;
}

/* musl's mbrtowc returns -2 for a valid UTF-8 prefix with no scalar yet;
 * iconv translates that condition to -1/EINVAL and leaves the prefix for a
 * subsequent call. */
static int check_incomplete_utf8(void) {
    iconv_t cd = open_utf8();
    if (cd == (iconv_t)-1) return 1;

    char input[] = {(char)0xc3};
    char output[8] = {0};
    char *in = input;
    char *out = output;
    size_t in_left = sizeof(input);
    size_t out_left = sizeof(output);
    errno = 0;

    size_t result = iconv(cd, &in, &in_left, &out, &out_left);
    if (result != (size_t)-1 || errno != EINVAL || in != input ||
        in_left != sizeof(input) || out != output || out_left != sizeof(output)) {
        int status = report("incomplete UTF-8", result, in, input, in_left,
                            out, output, out_left);
        iconv_close(cd);
        return status;
    }

    iconv_close(cd);
    return 0;
}

/* UTF-8 encodings of surrogate code points are malformed and must be
 * rejected, even though their three bytes have the shape of a UTF-8 scalar. */
static int check_surrogate_utf8(void) {
    iconv_t cd = open_utf8();
    if (cd == (iconv_t)-1) return 1;

    char input[] = {(char)0xed, (char)0xa0, (char)0x80};
    char output[8] = {0};
    char *in = input;
    char *out = output;
    size_t in_left = sizeof(input);
    size_t out_left = sizeof(output);
    errno = 0;

    size_t result = iconv(cd, &in, &in_left, &out, &out_left);
    if (result != (size_t)-1 || errno != EILSEQ || in != input ||
        in_left != sizeof(input) || out != output || out_left != sizeof(output)) {
        int status = report("UTF-8 surrogate", result, in, input, in_left,
                            out, output, out_left);
        iconv_close(cd);
        return status;
    }

    iconv_close(cd);
    return 0;
}

/* musl advances the caller's pointers for each completed scalar before an
 * error on the next scalar.  The invalid byte itself remains unconsumed. */
static int check_progress_before_invalid(void) {
    iconv_t cd = open_utf8();
    if (cd == (iconv_t)-1) return 1;

    char input[] = {'A', (char)0xc0};
    char output[4] = {0};
    char *in = input;
    char *out = output;
    size_t in_left = sizeof(input);
    size_t out_left = sizeof(output);
    errno = 0;

    size_t result = iconv(cd, &in, &in_left, &out, &out_left);
    if (result != (size_t)-1 || errno != EILSEQ || in != input + 1 ||
        in_left != 1 || out != output + 1 || out_left != 3 || output[0] != 'A') {
        int status = report("progress before invalid UTF-8", result, in, input,
                            in_left, out, output, out_left);
        iconv_close(cd);
        return status;
    }

    iconv_close(cd);
    return 0;
}

/* A destination with room for the first scalar only must report E2BIG while
 * retaining the committed progress and leaving the next scalar unconsumed. */
static int check_progress_before_e2big(void) {
    iconv_t cd = open_utf8();
    if (cd == (iconv_t)-1) return 1;

    char input[] = {'A', 'B'};
    char output[1] = {0};
    char *in = input;
    char *out = output;
    size_t in_left = sizeof(input);
    size_t out_left = sizeof(output);
    errno = 0;

    size_t result = iconv(cd, &in, &in_left, &out, &out_left);
    if (result != (size_t)-1 || errno != E2BIG || in != input + 1 ||
        in_left != 1 || out != output + 1 || out_left != 0 || output[0] != 'A') {
        int status = report("progress before E2BIG", result, in, input,
                            in_left, out, output, out_left);
        iconv_close(cd);
        return status;
    }

    iconv_close(cd);
    return 0;
}

int main(void) {
    int status;
    int failed = 0;

    status = check_incomplete_utf8();
    if (status != 0) failed = 1;
    status = check_surrogate_utf8();
    if (status != 0) failed = 1;
    status = check_progress_before_invalid();
    if (status != 0) failed = 1;
    status = check_progress_before_e2big();
    if (status != 0) failed = 1;

    if (failed != 0) return 1;

    puts("iconv error progress ok");
    return 0;
}
