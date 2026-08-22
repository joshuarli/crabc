/*
 * Deterministic selected stdio format/parse contract.
 *
 * This is deliberately the same narrow surface measured by the performance
 * fixture: buffered formatted output, repositioning, formatted input, and
 * bounded in-memory formatting/parsing.  It avoids ambient stdin/stdout and
 * leaves every formatted value observable before the temporary file is
 * removed.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int one_round(FILE *stream, unsigned int sequence)
{
    const int expected_signed = (int)sequence - 257;
    const unsigned int expected_unsigned = sequence * 7U + 100U;
    const unsigned int expected_hex = sequence + 0xf0U;
    const char *const expected_word = sequence & 1U ? "bravo" : "alpha";
    int signed_value = 0;
    unsigned int unsigned_value = 0;
    unsigned int hex_value = 0;
    char word[8] = {0};
    char formatted[16] = {0};
    int scan_signed = 0;
    int scan_tail = 0;
    char scan_word[8] = {0};

    if (fprintf(stream, "%d %u %x %s tail", expected_signed, expected_unsigned,
            expected_hex, expected_word) <= 0)
        return 1;
    if (fflush(stream) != 0 || fseek(stream, 0, SEEK_SET) != 0)
        return 2;
    if (fscanf(stream, "%d %u %x %7s", &signed_value, &unsigned_value,
            &hex_value, word) != 4)
        return 3;
    if (signed_value != expected_signed || unsigned_value != expected_unsigned
            || hex_value != expected_hex || strcmp(word, expected_word) != 0)
        return 4;
    if (fgetc(stream) != ' ' || fgetc(stream) != 't' || fgetc(stream) != 'a'
            || fgetc(stream) != 'i' || fgetc(stream) != 'l')
        return 5;
    if (snprintf(formatted, sizeof(formatted), "%d+%d=%d", 1, 2, 3) != 5
            || strcmp(formatted, "1+2=3") != 0)
        return 6;
    if (sscanf("42 hello 99", "%d %7s %d", &scan_signed, scan_word,
            &scan_tail) != 3)
        return 7;
    if (scan_signed != 42 || scan_tail != 99 || strcmp(scan_word, "hello") != 0)
        return 8;
    return 0;
}

/* A descriptor read must invalidate the position cached by the prior fseek. */
static int invalidated_position_round(const char *path)
{
    int value = 0;
    FILE *stream = fopen(path, "w+");

    if (stream == NULL)
        return 1;
    if (setvbuf(stream, NULL, _IONBF, 0) != 0)
        return 2;
    if (fputs("7 8 tail", stream) < 0 || fflush(stream) != 0
            || fseek(stream, 0, SEEK_SET) != 0)
        return 3;
    if (fgetc(stream) != '7')
        return 4;
    if (fscanf(stream, " %d", &value) != 1 || value != 8)
        return 5;
    if (fgetc(stream) != ' ' || fgetc(stream) != 't' || fgetc(stream) != 'a'
            || fgetc(stream) != 'i' || fgetc(stream) != 'l')
        return 6;
    return fclose(stream) == 0 ? 0 : 7;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    for (unsigned int sequence = 0; sequence < 513; ++sequence) {
        FILE *stream = fopen(argv[1], "w+");
        if (stream == NULL)
            return 10;
        const int status = one_round(stream, sequence);
        if (fclose(stream) != 0)
            return 11;
        if (status != 0)
            return 20 + status;
    }

    /*
     * A one-byte FILE buffer cannot retain the scanner's unread literal tail.
     * The implementation must use its seek-back route and still leave the
     * same characters available to the following fgetc calls.
     */
    {
        char buffer[1];
        FILE *stream = fopen(argv[1], "w+");
        if (stream == NULL)
            return 40;
        if (setvbuf(stream, buffer, _IOFBF, sizeof(buffer)) != 0)
            return 41;
        const int status = one_round(stream, 513);
        if (fclose(stream) != 0)
            return 42;
        if (status != 0)
            return 50 + status;
    }
    {
        const int status = invalidated_position_round(argv[1]);
        if (status != 0)
            return 60 + status;
    }
    if (unlink(argv[1]) != 0)
        return 30;
    puts("stdio format/parse contract ok");
    return 0;
}
