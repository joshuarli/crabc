/*
 * Finite direct-C observations for the selected POSIX-policy outcomes from
 * the untouched libc-test functional/wordexp source unit.
 *
 * The installed wordexp workload includes this file after
 * owned_wordexp_engine_probe.c.  Its one caller-facing function deliberately
 * emits observations rather than a PASS/SOURCE-RED verdict: the same object
 * is linked to pinned musl and the candidate, and the retained evidence
 * reader owns their separate exact policies.  A zero return means only that
 * all twenty calls, captures, marker checks, and environment restoration
 * completed.  It is never a semantic pass claim.
 */

#ifdef CRABC_WORDEXP_SOURCE_POLICY_PROBE_MAIN
#include "owned_wordexp_engine_probe.c"
#endif

#include <sys/stat.h>

#define WORDEXP_SOURCE_POLICY_MARKER "CRABC_WORDEXP_SOURCE_POLICY_MARKER"
#define WORDEXP_SOURCE_POLICY_DIAGNOSTIC_CAPACITY 16384
#define WORDEXP_SOURCE_POLICY_WORD_CAPACITY 4096
#define WORDEXP_SOURCE_POLICY_MAX_WORDS 16

struct wordexp_source_policy_case {
    const char *source;
    int flags;
};

/* Keep the C spellings in the review order.  In particular, the physical
 * newlines and backslashes are part of the source inputs, rather than display
 * notation reconstructed by a receipt reader. */
static const struct wordexp_source_policy_case wordexp_source_policy_cases[] = {
    { "$#", 0 },
    { ")", 0 },
    { "(", 0 },
    { "$UNSET ) $UNSET", WRDE_UNDEF },
    { "$UNSET ( $UNSET", WRDE_UNDEF },
    { "$UNSET $( $UNSET", WRDE_NOCMD | WRDE_UNDEF },
    { "$UNSET $(echo $UNSET", WRDE_NOCMD | WRDE_UNDEF },
    { "$UNSET ` $UNSET", WRDE_NOCMD | WRDE_UNDEF },
    { "#!@$^%&*(_+=<<-0>[{`${", WRDE_NOCMD },
    { "#'\necho x\\'", WRDE_NOCMD },
    { "a`b", WRDE_NOCMD },
    { "${X-\"$\"{A}B}", 0 },
    { "${X-$''}", WRDE_NOCMD },
    { "\"${X-$'$(cmd)'y}\"", WRDE_NOCMD },
    { "$((${X-$'$(cmd)'y}))", WRDE_NOCMD },
    { "${X=1} $((${X-'}))", WRDE_NOCMD },
    { "$((cmd #(\n)) )", WRDE_NOCMD },
    { "$((cmd #(\n))\n)", WRDE_NOCMD },
    { "x \\\n\\\n#);", WRDE_NOCMD },
    { "$((1 + #x))\n1))", WRDE_NOCMD },
};

static int wordexp_source_policy_write_all(
    int descriptor,
    const char *bytes,
    size_t length
)
{
    while (length != 0) {
        ssize_t written = write(descriptor, bytes, length);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 0;
        bytes += written;
        length -= (size_t)written;
    }
    return 1;
}

/* `cmd` is reachable only through the fixture's temporary PATH.  Any
 * erroneous evaluation of a NOCMD body therefore leaves a marker without
 * contributing word bytes or a diagnostic of its own. */
static int wordexp_source_policy_prepare_command(
    const struct wordexp_engine_marker_root *marker,
    char command_path[WORDEXP_ENGINE_PATH_CAPACITY]
)
{
    static const char command[] =
        "#!/bin/sh\n"
        ": > \"$" WORDEXP_SOURCE_POLICY_MARKER "\"\n";
    int descriptor;
    int written;

    written = snprintf(command_path, WORDEXP_ENGINE_PATH_CAPACITY, "%s/cmd",
        marker->directory);
    if (written < 0 || (size_t)written >= WORDEXP_ENGINE_PATH_CAPACITY)
        return 0;
    descriptor = open(command_path, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (descriptor < 0)
        return 0;
    if (!wordexp_source_policy_write_all(descriptor, command,
            sizeof command - 1) || fchmod(descriptor, 0700) != 0)
    {
        (void)close(descriptor);
        (void)unlink(command_path);
        command_path[0] = 0;
        return 0;
    }
    if (close(descriptor) != 0) {
        (void)unlink(command_path);
        command_path[0] = 0;
        return 0;
    }
    return 1;
}

static size_t wordexp_source_policy_bounded_length(
    const char *text,
    size_t capacity
)
{
    size_t length;

    for (length = 0; length < capacity; ++length) {
        if (text[length] == 0)
            break;
    }
    return length;
}

static int wordexp_source_policy_emit_hex(
    const unsigned char *bytes,
    size_t length
)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < length; ++index) {
        if (fputc(digits[bytes[index] >> 4], stdout) == EOF ||
            fputc(digits[bytes[index] & 15], stdout) == EOF)
        {
            return 0;
        }
    }
    return 1;
}

static int wordexp_source_policy_emit_words(
    const wordexp_t *words,
    int status,
    int *success_record_valid
)
{
    size_t index;

    *success_record_valid = 0;
    if (status != 0) {
        if (fputc('-', stdout) == EOF)
            return 0;
        return 1;
    }
    if (words->we_wordc > WORDEXP_SOURCE_POLICY_MAX_WORDS ||
        words->we_wordv == NULL)
    {
        return fputs("!record", stdout) != EOF;
    }
    if (words->we_offs != 0)
        return fputs("!offset", stdout) != EOF;
    if (words->we_wordc == 0) {
        if (words->we_wordv[0] != NULL)
            return fputs("!unterminated", stdout) != EOF;
        *success_record_valid = 1;
        return fputc('-', stdout) != EOF;
    }
    for (index = 0; index < words->we_wordc; ++index) {
        char *word = words->we_wordv[index];
        size_t length;

        if (index != 0 && fputc(',', stdout) == EOF)
            return 0;
        if (word == NULL)
            return fputs("!null", stdout) != EOF;
        length = wordexp_source_policy_bounded_length(word,
            WORDEXP_SOURCE_POLICY_WORD_CAPACITY);
        if (length == WORDEXP_SOURCE_POLICY_WORD_CAPACITY)
            return fputs("!unterminated", stdout) != EOF;
        if (printf("%zu:", length) < 0 ||
            !wordexp_source_policy_emit_hex((const unsigned char *)word, length))
        {
            return 0;
        }
    }
    if (words->we_wordv[words->we_wordc] != NULL)
        return fputs("!unterminated", stdout) != EOF;
    *success_record_valid = 1;
    return 1;
}

static int wordexp_source_policy_marker_effect(
    const struct wordexp_engine_marker_root *marker,
    int *effect
)
{
    if (access(marker->marker, F_OK) == 0) {
        *effect = 1;
        return 1;
    }
    if (errno == ENOENT) {
        *effect = 0;
        return 1;
    }
    return 0;
}

/* `wordhex` is a comma-separated list of `byte-length:lowercase-hex` words.
 * `-` means no success words (or a nonzero wordexp status), so an empty word
 * remains distinguishable as `0:`.  `stderrhex` is `-` only for an empty
 * captured diagnostic. */
static int wordexp_source_policy_emit_observation(
    size_t case_number,
    int status,
    const wordexp_t *words,
    const char *diagnostics,
    size_t diagnostics_length,
    int effect,
    int environment_effect,
    int *success_record_valid
)
{
    if (printf("owned-wordexp-source-policy: case=%02zu status=%d count=%zu ",
            case_number, status, words->we_wordc) < 0 ||
        fputs("wordhex=", stdout) == EOF ||
        !wordexp_source_policy_emit_words(words, status, success_record_valid) ||
        fputs(" stderrhex=", stdout) == EOF)
    {
        return 0;
    }
    if (diagnostics_length == 0) {
        if (fputc('-', stdout) == EOF)
            return 0;
    } else if (!wordexp_source_policy_emit_hex(
            (const unsigned char *)diagnostics, diagnostics_length))
    {
        return 0;
    }
    return printf(" effect=%d env=%d\n", effect, environment_effect) >= 0;
}

/* This is intentionally callable from the including installed workload.  Its
 * exit value reports fixture integrity only; semantic interpretation belongs
 * to the retained candidate/oracle reader described beside this source. */
static int wordexp_source_policy_run(void)
{
    struct wordexp_engine_environment_slot x = { 0 };
    struct wordexp_engine_environment_slot unset = { 0 };
    struct wordexp_engine_environment_slot path = { 0 };
    struct wordexp_engine_environment_slot marker_variable = { 0 };
    struct wordexp_engine_marker_root marker = { { 0 }, { 0 } };
    char command_path[WORDEXP_ENGINE_PATH_CAPACITY] = { 0 };
    size_t index;
    int result = 1;

    if (wordexp_engine_save_environment(&x, "X") != 0 ||
        wordexp_engine_save_environment(&unset, "UNSET") != 0 ||
        wordexp_engine_save_environment(&path, "PATH") != 0 ||
        wordexp_engine_save_environment(&marker_variable,
            WORDEXP_SOURCE_POLICY_MARKER) != 0)
    {
        goto cleanup;
    }
    if (!wordexp_engine_prepare_marker(&marker) ||
        !wordexp_source_policy_prepare_command(&marker, command_path) ||
        unsetenv("X") != 0 || unsetenv("UNSET") != 0 ||
        setenv("PATH", marker.directory, 1) != 0 ||
        setenv(WORDEXP_SOURCE_POLICY_MARKER, marker.marker, 1) != 0)
    {
        result = 2;
        goto cleanup;
    }

    for (index = 0; index < sizeof wordexp_source_policy_cases /
            sizeof wordexp_source_policy_cases[0]; ++index)
    {
        const struct wordexp_source_policy_case *test =
            &wordexp_source_policy_cases[index];
        char diagnostics[WORDEXP_SOURCE_POLICY_DIAGNOSTIC_CAPACITY];
        size_t diagnostics_length = 0;
        int status = WRDE_NOSPACE;
        int saved_errno = 0;
        int stream_error_unchanged = 0;
        int effect;
        int environment_effect;
        int success_record_valid = 0;
        wordexp_t words = { 0 };

        if (!wordexp_engine_clear_marker(&marker) ||
            !wordexp_engine_captured_wordexp(test->source, &words, test->flags,
                diagnostics, sizeof diagnostics, &diagnostics_length, &status,
                &saved_errno, &stream_error_unchanged) ||
            diagnostics_length == sizeof diagnostics - 1 ||
            !stream_error_unchanged ||
            !wordexp_source_policy_marker_effect(&marker, &effect))
        {
            result = 3;
            goto cleanup;
        }
        environment_effect = getenv("X") != NULL || getenv("UNSET") != NULL;
        if (!wordexp_source_policy_emit_observation(index + 1, status, &words,
                diagnostics, diagnostics_length, effect, environment_effect,
                &success_record_valid) ||
            !wordexp_engine_clear_marker(&marker))
        {
            if (status == 0 && success_record_valid)
                wordfree(&words);
            result = 3;
            goto cleanup;
        }
        (void)saved_errno;
        if (status == 0 && success_record_valid)
            wordfree(&words);
    }
    if (getenv("X") != NULL || getenv("UNSET") != NULL || fflush(stdout) != 0) {
        result = 4;
        goto cleanup;
    }
    result = 0;

cleanup:
    if (command_path[0] != 0 && unlink(command_path) != 0 && errno != ENOENT)
        result = 5;
    if (wordexp_engine_remove_marker(&marker) != 0)
        result = 6;
    if (wordexp_engine_restore_environment(&marker_variable) != 0 ||
        wordexp_engine_restore_environment(&path) != 0 ||
        wordexp_engine_restore_environment(&unset) != 0 ||
        wordexp_engine_restore_environment(&x) != 0)
    {
        return 7;
    }
    return result;
}

#ifdef CRABC_WORDEXP_SOURCE_POLICY_PROBE_MAIN
int main(void)
{
    return wordexp_source_policy_run();
}
#endif
