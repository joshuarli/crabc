/*
 * Direct C-ABI regressions for the selected owned x86 wordexp provider.
 *
 * This source is included after the ordinary
 * owned_wordexp_probe.c helpers, and its standalone main exists only when
 * CRABC_WORDEXP_ENGINE_PROBE_MAIN is defined. Every helper name stays in the
 * wordexp_engine_ namespace to keep its C-boundary cases findable together.
 *
 * The normal selectors are public-header C calls and can record fixed musl
 * source RED observations separately from required candidate passes. The result-allocation selector is
 * a different disposable build: it exists only when
 * CRABC_WORDEXP_RESULT_PRIVATE_TEST declares the two fixture-only Rust test
 * controls. No normal product declares, links, or exports those controls.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "owned wordexp engine probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wordexp.h>

_Static_assert(sizeof(wordexp_t) == 24, "x86-64 wordexp_t layout");
_Static_assert(_Alignof(wordexp_t) == 8, "x86-64 wordexp_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wordexp),
    int (*)(const char *restrict, wordexp_t *restrict, int)),
    "wordexp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wordfree),
    void (*)(wordexp_t *)), "wordfree declaration");

#define WORDEXP_ENGINE_UNSET "CRABC_WORDEXP_ENGINE_UNSET"
#define WORDEXP_ENGINE_SELECTOR "CRABC_WORDEXP_ENGINE_SELECTOR"
#define WORDEXP_ENGINE_EMPTY "CRABC_WORDEXP_ENGINE_EMPTY"
#define WORDEXP_ENGINE_MARKER "CRABC_WORDEXP_ENGINE_MARKER"
#define WORDEXP_ENGINE_INVALID "CRABC_WORDEXP_ENGINE_INVALID"
#define WORDEXP_ENGINE_INVALID_ONLY "CRABC_WORDEXP_ENGINE_INVALID_ONLY"
#define WORDEXP_ENGINE_PATH_CAPACITY 4096
#define WORDEXP_ENGINE_BUDGET_LIMIT 128

enum {
    WORDEXP_ENGINE_PASS = 0,
    WORDEXP_ENGINE_SOURCE_RED_UNDEF = -1,
    WORDEXP_ENGINE_SOURCE_RED_DIAGNOSTIC = -2,
    WORDEXP_ENGINE_SOURCE_RED_NOCMD = -3,
    WORDEXP_ENGINE_SOURCE_RED_SIGPIPE = -4,
    WORDEXP_ENGINE_SOURCE_RED_QUIET_DIAGNOSTIC = -5,
};

struct wordexp_engine_environment_slot {
    const char *name;
    char *saved_value;
    int was_set;
};

struct wordexp_engine_marker_root {
    char directory[WORDEXP_ENGINE_PATH_CAPACITY];
    char marker[WORDEXP_ENGINE_PATH_CAPACITY];
};

struct wordexp_engine_record_snapshot {
    char **vector;
    size_t count;
    size_t offsets;
    char words[2][64];
};

struct wordexp_engine_stderr_capture {
    int saved_stderr;
    int read_end;
    int stream_error_before;
};

static int wordexp_engine_save_environment(
    struct wordexp_engine_environment_slot *slot,
    const char *name
)
{
    const char *value = getenv(name);

    slot->name = name;
    slot->saved_value = NULL;
    slot->was_set = value != NULL;
    if (value == NULL)
        return 0;

    size_t length = strlen(value) + 1;
    if (length == 0) {
        slot->name = NULL;
        slot->was_set = 0;
        return -1;
    }
    slot->saved_value = malloc(length);
    if (slot->saved_value == NULL) {
        slot->name = NULL;
        slot->was_set = 0;
        return -1;
    }
    memcpy(slot->saved_value, value, length);
    return 0;
}

static int wordexp_engine_restore_environment(
    struct wordexp_engine_environment_slot *slot
)
{
    int result;

    if (slot->name == NULL)
        return 0;
    if (slot->was_set)
        result = setenv(slot->name, slot->saved_value, 1);
    else
        result = unsetenv(slot->name);
    free(slot->saved_value);
    slot->name = NULL;
    slot->saved_value = NULL;
    return result;
}

/* The marker path is passed through one quoted environment expansion, never
 * spliced into shell source. The fixture requires the runner's absolute
 * TMPDIR and leaves only this private mkdtemp directory beneath it. */
static int wordexp_engine_prepare_marker(
    struct wordexp_engine_marker_root *root
)
{
    const char *temporary = getenv("TMPDIR");
    int written;

    if (temporary == NULL || temporary[0] != '/')
        return 0;
    written = snprintf(root->directory, sizeof root->directory,
        "%s/wordexp-engine.XXXXXX", temporary);
    if (written < 0 || (size_t)written >= sizeof root->directory)
        return 0;
    if (mkdtemp(root->directory) == NULL)
        return 0;
    written = snprintf(root->marker, sizeof root->marker, "%s/marker",
        root->directory);
    if (written < 0 || (size_t)written >= sizeof root->marker) {
        (void)rmdir(root->directory);
        root->directory[0] = 0;
        return 0;
    }
    return 1;
}

static int wordexp_engine_marker_missing(
    const struct wordexp_engine_marker_root *root
)
{
    if (access(root->marker, F_OK) == 0)
        return 0;
    return errno == ENOENT;
}

static int wordexp_engine_clear_marker(
    const struct wordexp_engine_marker_root *root
)
{
    if (unlink(root->marker) != 0 && errno != ENOENT)
        return 0;
    return wordexp_engine_marker_missing(root);
}

static int wordexp_engine_marker_is_one_x(
    const struct wordexp_engine_marker_root *root
)
{
    char bytes[2];
    int descriptor;
    ssize_t count;

    descriptor = open(root->marker, O_RDONLY);
    if (descriptor < 0)
        return 0;
    count = read(descriptor, bytes, sizeof bytes);
    if (close(descriptor) != 0)
        return 0;
    return count == 1 && bytes[0] == 'x';
}

static int wordexp_engine_remove_marker(
    struct wordexp_engine_marker_root *root
)
{
    int result = 0;

    if (root->directory[0] == 0)
        return 0;
    if (unlink(root->marker) != 0 && errno != ENOENT)
        result = -1;
    if (rmdir(root->directory) != 0)
        result = -1;
    root->directory[0] = 0;
    root->marker[0] = 0;
    return result;
}

/* A null vector is a valid fresh WRDE_NOSPACE zero prefix. Any non-null
 * vector must have all requested leading nulls and a final null terminator. */
static int wordexp_engine_check_prefix(
    const wordexp_t *words,
    size_t offsets,
    const char *const expected[],
    size_t expected_count
)
{
    size_t index;

    if (words->we_offs != offsets || words->we_wordc > expected_count)
        return 0;
    if (words->we_wordv == NULL)
        return words->we_wordc == 0;
    for (index = 0; index < offsets; ++index) {
        if (words->we_wordv[index] != NULL)
            return 0;
    }
    for (index = 0; index < words->we_wordc; ++index) {
        char *word = words->we_wordv[offsets + index];
        if (word == NULL || strcmp(word, expected[index]) != 0)
            return 0;
    }
    return words->we_wordv[offsets + words->we_wordc] == NULL;
}

static int wordexp_engine_check_complete(
    const wordexp_t *words,
    size_t offsets,
    const char *const expected[],
    size_t expected_count
)
{
    return words->we_wordv != NULL && words->we_wordc == expected_count &&
        wordexp_engine_check_prefix(words, offsets, expected, expected_count);
}

static int wordexp_engine_check_empty_error(const wordexp_t *words)
{
    return words->we_wordc == 0 && words->we_wordv == NULL;
}

static int wordexp_engine_release(
    wordexp_t *words,
    size_t expected_offsets
)
{
    errno = E2BIG;
    wordfree(words);
    return errno == E2BIG && words->we_wordc == 0 && words->we_wordv == NULL &&
        words->we_offs == expected_offsets;
}

/* A checked release has already called wordfree and cleared its record. The
 * ordinary cleanup path only needs to dispose of a still-published vector. */
static void wordexp_engine_discard(wordexp_t *words)
{
    if (words->we_wordv != NULL)
        wordfree(words);
}

static int wordexp_engine_snapshot_record(
    const wordexp_t *words,
    struct wordexp_engine_record_snapshot *snapshot
)
{
    size_t index;

    if (words->we_wordv == NULL || words->we_wordc != 2)
        return 0;
    snapshot->vector = words->we_wordv;
    snapshot->count = words->we_wordc;
    snapshot->offsets = words->we_offs;
    for (index = 0; index < 2; ++index) {
        const char *word = words->we_wordv[words->we_offs + index];
        size_t length;

        if (word == NULL)
            return 0;
        length = strlen(word);
        if (length >= sizeof snapshot->words[index])
            return 0;
        memcpy(snapshot->words[index], word, length + 1);
    }
    return words->we_wordv[words->we_offs + 2] == NULL;
}

static int wordexp_engine_snapshot_is_unchanged(
    const wordexp_t *words,
    const struct wordexp_engine_record_snapshot *snapshot
)
{
    size_t index;

    if (words->we_wordv != snapshot->vector ||
        words->we_wordc != snapshot->count ||
        words->we_offs != snapshot->offsets)
        return 0;
    for (index = 0; index < snapshot->offsets; ++index) {
        if (words->we_wordv[index] != NULL)
            return 0;
    }
    for (index = 0; index < 2; ++index) {
        char *word = words->we_wordv[snapshot->offsets + index];
        if (word == NULL || strcmp(word, snapshot->words[index]) != 0)
            return 0;
    }
    return words->we_wordv[snapshot->offsets + 2] == NULL;
}

static int wordexp_engine_begin_stderr_capture(
    struct wordexp_engine_stderr_capture *capture
)
{
    int descriptors[2] = { -1, -1 };

    capture->saved_stderr = -1;
    capture->read_end = -1;
    if (pipe(descriptors) != 0)
        return 0;
    capture->saved_stderr = dup(STDERR_FILENO);
    if (capture->saved_stderr < 0 ||
        dup2(descriptors[1], STDERR_FILENO) != STDERR_FILENO ||
        close(descriptors[1]) != 0)
    {
        if (capture->saved_stderr >= 0)
            (void)close(capture->saved_stderr);
        (void)close(descriptors[0]);
        if (descriptors[1] >= 0)
            (void)close(descriptors[1]);
        return 0;
    }
    capture->read_end = descriptors[0];
    capture->stream_error_before = ferror(stderr);
    return 1;
}

static int wordexp_engine_finish_stderr_capture(
    struct wordexp_engine_stderr_capture *capture,
    char *output,
    size_t output_capacity,
    size_t *output_length,
    int *stream_error_unchanged
)
{
    ssize_t count;

    if (output_capacity == 0 ||
        dup2(capture->saved_stderr, STDERR_FILENO) != STDERR_FILENO ||
        close(capture->saved_stderr) != 0)
    {
        if (capture->read_end >= 0)
            (void)close(capture->read_end);
        return 0;
    }
    capture->saved_stderr = -1;
    do {
        count = read(capture->read_end, output, output_capacity - 1);
    } while (count < 0 && errno == EINTR);
    if (close(capture->read_end) != 0 || count < 0)
        return 0;
    capture->read_end = -1;
    output[count] = 0;
    *output_length = (size_t)count;
    *stream_error_unchanged = ferror(stderr) == capture->stream_error_before;
    return 1;
}

static int wordexp_engine_captured_wordexp(
    const char *source,
    wordexp_t *words,
    int flags,
    char *diagnostics,
    size_t diagnostics_capacity,
    size_t *diagnostics_length,
    int *wordexp_result,
    int *wordexp_errno,
    int *stream_error_unchanged
)
{
    struct wordexp_engine_stderr_capture capture;

    if (!wordexp_engine_begin_stderr_capture(&capture))
        return 0;
    errno = E2BIG;
    *wordexp_result = wordexp(source, words, flags);
    *wordexp_errno = errno;
    return wordexp_engine_finish_stderr_capture(&capture, diagnostics,
        diagnostics_capacity, diagnostics_length, stream_error_unchanged);
}

/* Retain the two output regressions found by the unchanged upstream unit:
 * unrecognized dollar spellings remain literal once, and a selected unquoted
 * parameter default performs tilde expansion using the current HOME. The
 * delimiter controls retain arithmetic across removable line joins. */
static int wordexp_engine_literals_case(void)
{
    static const char *const sources[] = {
        "\"$) $} $\\ $\"", "${" WORDEXP_ENGINE_UNSET "-~}",
        "$((1+2)\\\n)", "$(\\\n(1+2))"
    };
    static const char *const expected[] = { "$) $} $\\ $", "/wordexp-home", "3", "3" };
    struct wordexp_engine_environment_slot variable = { 0 };
    struct wordexp_engine_environment_slot home = { 0 };
    wordexp_t words = { 0 };
    size_t index;
    int result = 1;

    if (wordexp_engine_save_environment(&variable, WORDEXP_ENGINE_UNSET) != 0 ||
        wordexp_engine_save_environment(&home, "HOME") != 0)
        goto cleanup;
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0 || setenv("HOME", "/wordexp-home", 1) != 0) {
        result = 2;
        goto cleanup;
    }
    for (index = 0; index < sizeof sources / sizeof sources[0]; ++index) {
        errno = E2BIG;
        if (wordexp(sources[index], &words, 0) != 0 || errno != E2BIG ||
            !wordexp_engine_check_complete(&words, 0, &expected[index], 1) ||
            !wordexp_engine_release(&words, 0)) {
            result = 3 + (int)index;
            goto cleanup;
        }
    }
    result = WORDEXP_ENGINE_PASS;
cleanup:
    wordexp_engine_discard(&words);
    if (wordexp_engine_restore_environment(&home) != 0 ||
        wordexp_engine_restore_environment(&variable) != 0)
        return 7;
    return result;
}

static int wordexp_engine_undef_case(void)
{
    static const char *const empty[] = { "" };
    static const char *const lazy[] = { "default", "assigned", "assigned" };
    struct wordexp_engine_environment_slot variable = { 0 };
    wordexp_t words = { 0 };
    int status;
    int saved_errno;
    int result = 1;

    if (wordexp_engine_save_environment(&variable, WORDEXP_ENGINE_UNSET) != 0)
        return 1;
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0) {
        result = 2;
        goto cleanup;
    }

    errno = E2BIG;
    status = wordexp("$" WORDEXP_ENGINE_UNSET, &words, WRDE_UNDEF);
    saved_errno = errno;
    /* Pinned musl's selected source accepts this as a zero-field success. It
     * is a named source RED, never an alternative candidate pass. */
    if (status == 0 && saved_errno == E2BIG &&
        wordexp_engine_check_prefix(&words, 0, NULL, 0) &&
        wordexp_engine_release(&words, 0))
    {
        result = WORDEXP_ENGINE_SOURCE_RED_UNDEF;
        goto cleanup;
    }
    if (status != WRDE_BADVAL || saved_errno != E2BIG ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 3;
        goto cleanup;
    }

    if (setenv(WORDEXP_ENGINE_UNSET, "", 1) != 0) {
        result = 4;
        goto cleanup;
    }
    errno = E2BIG;
    status = wordexp("\"$" WORDEXP_ENGINE_UNSET "\"", &words, WRDE_UNDEF);
    saved_errno = errno;
    if (status != 0 || saved_errno != E2BIG ||
        !wordexp_engine_check_complete(&words, 0, empty, 1) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 5;
        goto cleanup;
    }

    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0) {
        result = 6;
        goto cleanup;
    }
    errno = E2BIG;
    status = wordexp(
        "${" WORDEXP_ENGINE_UNSET ":+$CRABC_WORDEXP_ENGINE_UNSELECTED} "
        "${" WORDEXP_ENGINE_UNSET ":-default} "
        "${" WORDEXP_ENGINE_UNSET ":=assigned} $" WORDEXP_ENGINE_UNSET,
        &words, WRDE_UNDEF
    );
    saved_errno = errno;
    if (status != 0 || saved_errno != E2BIG ||
        !wordexp_engine_check_complete(&words, 0, lazy, 3) ||
        getenv(WORDEXP_ENGINE_UNSET) != NULL ||
        !wordexp_engine_release(&words, 0))
    {
        result = 7;
        goto cleanup;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup:
    wordexp_engine_discard(&words);
    if (wordexp_engine_restore_environment(&variable) != 0)
        return 8;
    return result;
}

static int wordexp_engine_append_rollback_case(void)
{
    static const char *const initial[] = { "old-one", "old-two" };
    static const char *const source_red_words[] = {
        "old-one", "old-two", "new-root"
    };
    struct wordexp_engine_environment_slot variable = { 0 };
    struct wordexp_engine_record_snapshot snapshot;
    wordexp_t words = { 0 };
    int status;
    int saved_errno;
    int result = 1;

    if (wordexp_engine_save_environment(&variable, WORDEXP_ENGINE_UNSET) != 0)
        return 1;
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0) {
        result = 2;
        goto cleanup;
    }
    words.we_offs = 2;
    if (wordexp("old-one old-two", &words, WRDE_DOOFFS) != 0 ||
        !wordexp_engine_check_complete(&words, 2, initial, 2) ||
        !wordexp_engine_snapshot_record(&words, &snapshot))
    {
        result = 3;
        goto cleanup_words;
    }

    errno = E2BIG;
    status = wordexp("new-root $" WORDEXP_ENGINE_UNSET, &words,
        WRDE_DOOFFS | WRDE_APPEND | WRDE_UNDEF);
    saved_errno = errno;
    if (status == 0 && saved_errno == E2BIG &&
        wordexp_engine_check_complete(&words, 2, source_red_words, 3) &&
        wordexp_engine_release(&words, 2)) {
        /* This exact three-word record is the current source's omitted
         * WRDE_UNDEF classification, not a fallback label for any success. */
        result = WORDEXP_ENGINE_SOURCE_RED_UNDEF;
        goto cleanup;
    }
    if (status != WRDE_BADVAL || saved_errno != E2BIG ||
        !wordexp_engine_snapshot_is_unchanged(&words, &snapshot))
    {
        result = 4;
        goto cleanup_words;
    }

    errno = E2BIG;
    status = wordexp("new-root ${" WORDEXP_ENGINE_UNSET ":?generic}", &words,
        WRDE_DOOFFS | WRDE_APPEND);
    saved_errno = errno;
    if (status != WRDE_SYNTAX || saved_errno != E2BIG ||
        !wordexp_engine_snapshot_is_unchanged(&words, &snapshot))
    {
        result = 5;
        goto cleanup_words;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup_words:
    if (!wordexp_engine_release(&words, 2))
        result = 6;
cleanup:
    wordexp_engine_discard(&words);
    if (wordexp_engine_restore_environment(&variable) != 0)
        return 7;
    return result;
}

static int wordexp_engine_reuse_offsets_case(void)
{
    static const char *const initial[] = { "old" };
    static const char *const replacement[] = { "replacement" };
    wordexp_t words = { 0 };

    words.we_offs = 3;
    if (wordexp("old", &words, WRDE_DOOFFS) != 0 ||
        !wordexp_engine_check_complete(&words, 3, initial, 1))
    {
        wordexp_engine_discard(&words);
        return 1;
    }
    if (wordexp("replacement", &words, WRDE_REUSE | WRDE_DOOFFS) != 0 ||
        !wordexp_engine_check_complete(&words, 3, replacement, 1))
    {
        wordexp_engine_discard(&words);
        return 2;
    }
    return wordexp_engine_release(&words, 3) ? WORDEXP_ENGINE_PASS : 3;
}

static int wordexp_engine_parameter_word_case(void)
{
    static const char selected[] =
        "${" WORDEXP_ENGINE_UNSET ":?$(printf x >> \"$" WORDEXP_ENGINE_MARKER "\")}";
    static const char unselected[] =
        "${" WORDEXP_ENGINE_SELECTOR ":+${" WORDEXP_ENGINE_UNSET
        ":?$(printf x >> \"$" WORDEXP_ENGINE_MARKER "\")}}";
    struct wordexp_engine_environment_slot unset_variable = { 0 };
    struct wordexp_engine_environment_slot selector = { 0 };
    struct wordexp_engine_environment_slot marker_variable = { 0 };
    struct wordexp_engine_marker_root marker = { { 0 }, { 0 } };
    char diagnostics[512];
    size_t diagnostics_length;
    wordexp_t words = { 0 };
    int status;
    int saved_errno;
    int stream_error_unchanged;
    int nocmd_source_red = 0;
    int result = 1;

    if (wordexp_engine_save_environment(&unset_variable, WORDEXP_ENGINE_UNSET) != 0 ||
        wordexp_engine_save_environment(&selector, WORDEXP_ENGINE_SELECTOR) != 0 ||
        wordexp_engine_save_environment(&marker_variable, WORDEXP_ENGINE_MARKER) != 0)
    {
        result = 1;
        goto cleanup;
    }
    if (!wordexp_engine_prepare_marker(&marker)) {
        result = 2;
        goto cleanup;
    }
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0 ||
        unsetenv(WORDEXP_ENGINE_SELECTOR) != 0 ||
        setenv(WORDEXP_ENGINE_MARKER, marker.marker, 1) != 0)
    {
        result = 3;
        goto cleanup;
    }

    if (!wordexp_engine_clear_marker(&marker)) {
        result = 4;
        goto cleanup;
    }
    errno = E2BIG;
    if (!wordexp_engine_captured_wordexp(selected, &words, 0, diagnostics,
            sizeof diagnostics, &diagnostics_length, &status, &saved_errno,
            &stream_error_unchanged) ||
        status != WRDE_SYNTAX || saved_errno != E2BIG ||
        !stream_error_unchanged ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0) ||
        !wordexp_engine_marker_is_one_x(&marker))
    {
        result = 5;
        goto cleanup;
    }

    if (!wordexp_engine_clear_marker(&marker)) {
        result = 6;
        goto cleanup;
    }
    errno = E2BIG;
    status = wordexp(unselected, &words, 0);
    saved_errno = errno;
    if (status != 0 || saved_errno != E2BIG ||
        !wordexp_engine_check_complete(&words, 0, NULL, 0) ||
        !wordexp_engine_release(&words, 0) ||
        !wordexp_engine_marker_missing(&marker))
    {
        result = 7;
        goto cleanup;
    }

    if (!wordexp_engine_clear_marker(&marker)) {
        result = 8;
        goto cleanup;
    }
    errno = E2BIG;
    status = wordexp(selected, &words, WRDE_NOCMD);
    saved_errno = errno;
    if (status == WRDE_BADCHAR && saved_errno == E2BIG &&
        wordexp_engine_check_empty_error(&words) &&
        wordexp_engine_release(&words, 0) &&
        wordexp_engine_marker_missing(&marker)) {
        /* This is the exact pinned-musl parse classification. It remains a
         * source observation only after both selected and skipped branches
         * agree, because the candidate contract is WRDE_CMDSUB for both. */
        nocmd_source_red = 1;
    } else if (status != WRDE_CMDSUB || saved_errno != E2BIG ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0) ||
        !wordexp_engine_marker_missing(&marker)) {
        result = 9;
        goto cleanup;
    }

    if (!wordexp_engine_clear_marker(&marker)) {
        result = 10;
        goto cleanup;
    }
    errno = E2BIG;
    status = wordexp(unselected, &words, WRDE_NOCMD);
    saved_errno = errno;
    if (nocmd_source_red) {
        if (status == WRDE_BADCHAR && saved_errno == E2BIG &&
            wordexp_engine_check_empty_error(&words) &&
            wordexp_engine_release(&words, 0) &&
            wordexp_engine_marker_missing(&marker)) {
            result = WORDEXP_ENGINE_SOURCE_RED_NOCMD;
            goto cleanup;
        }
        result = 11;
        goto cleanup;
    }
    if (status != WRDE_CMDSUB || saved_errno != E2BIG ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0) ||
        !wordexp_engine_marker_missing(&marker))
    {
        result = 11;
        goto cleanup;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup:
    wordexp_engine_discard(&words);
    if (wordexp_engine_remove_marker(&marker) != 0)
        result = 12;
    if (wordexp_engine_restore_environment(&marker_variable) != 0 ||
        wordexp_engine_restore_environment(&selector) != 0 ||
        wordexp_engine_restore_environment(&unset_variable) != 0)
    {
        return 13;
    }
    return result;
}

static int wordexp_engine_diagnostics_case(void)
{
    static const char shown_source[] = "${" WORDEXP_ENGINE_UNSET ":?shown}";
    static const char omitted_source[] = "${" WORDEXP_ENGINE_UNSET ":?}";
    static const char explicit_empty_source[] = "${" WORDEXP_ENGINE_UNSET ":?\"\"}";
    static const char shown[] = "wordexp: " WORDEXP_ENGINE_UNSET ": shown\n";
    static const char omitted[] =
        "wordexp: " WORDEXP_ENGINE_UNSET ": parameter is unset or empty\n";
    static const char explicit_empty[] = "wordexp: " WORDEXP_ENGINE_UNSET ": \n";
    static const char source_shell_shown[] =
        "sh: eval: line 0: " WORDEXP_ENGINE_UNSET ": shown\n";
    struct wordexp_engine_environment_slot variable = { 0 };
    char diagnostics[512];
    size_t diagnostics_length;
    wordexp_t words = { 0 };
    int status;
    int saved_errno;
    int stream_error_unchanged;
    int result = 1;

    if (wordexp_engine_save_environment(&variable, WORDEXP_ENGINE_UNSET) != 0)
        return 1;
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0) {
        result = 2;
        goto cleanup;
    }

    if (!wordexp_engine_captured_wordexp(shown_source, &words, 0,
            diagnostics, sizeof diagnostics, &diagnostics_length, &status,
            &saved_errno, &stream_error_unchanged)) {
        result = 3;
        goto cleanup;
    }
    if (status == WRDE_SYNTAX && saved_errno == E2BIG &&
        diagnostics_length == strlen(source_shell_shown) &&
        strcmp(diagnostics, source_shell_shown) == 0 &&
        stream_error_unchanged &&
        wordexp_engine_check_empty_error(&words) &&
        wordexp_engine_release(&words, 0)) {
        result = WORDEXP_ENGINE_SOURCE_RED_QUIET_DIAGNOSTIC;
        goto cleanup;
    }
    if (status != WRDE_SYNTAX || saved_errno != E2BIG ||
        diagnostics_length != 0 || !stream_error_unchanged ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 3;
        goto cleanup;
    }

    if (!wordexp_engine_captured_wordexp(shown_source, &words, WRDE_SHOWERR,
            diagnostics, sizeof diagnostics, &diagnostics_length, &status,
            &saved_errno, &stream_error_unchanged))
    {
        result = 4;
        goto cleanup;
    }
    if (status == WRDE_SYNTAX && saved_errno == E2BIG &&
        stream_error_unchanged &&
        wordexp_engine_check_empty_error(&words) &&
        wordexp_engine_release(&words, 0) &&
        diagnostics_length == strlen(source_shell_shown) &&
        strcmp(diagnostics, source_shell_shown) == 0)
    {
        result = WORDEXP_ENGINE_SOURCE_RED_DIAGNOSTIC;
        goto cleanup;
    }
    if (status != WRDE_SYNTAX || saved_errno != E2BIG ||
        !stream_error_unchanged || diagnostics_length != strlen(shown) ||
        strcmp(diagnostics, shown) != 0 ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 5;
        goto cleanup;
    }

    if (!wordexp_engine_captured_wordexp(omitted_source, &words, WRDE_SHOWERR,
            diagnostics, sizeof diagnostics, &diagnostics_length, &status,
            &saved_errno, &stream_error_unchanged) ||
        status != WRDE_SYNTAX || saved_errno != E2BIG ||
        !stream_error_unchanged || diagnostics_length != strlen(omitted) ||
        strcmp(diagnostics, omitted) != 0 ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 6;
        goto cleanup;
    }

    if (!wordexp_engine_captured_wordexp(explicit_empty_source, &words,
            WRDE_SHOWERR, diagnostics, sizeof diagnostics, &diagnostics_length,
            &status, &saved_errno, &stream_error_unchanged) ||
        status != WRDE_SYNTAX || saved_errno != E2BIG ||
        !stream_error_unchanged || diagnostics_length != strlen(explicit_empty) ||
        strcmp(diagnostics, explicit_empty) != 0 ||
        !wordexp_engine_check_empty_error(&words) ||
        !wordexp_engine_release(&words, 0))
    {
        result = 7;
        goto cleanup;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup:
    wordexp_engine_discard(&words);
    if (wordexp_engine_restore_environment(&variable) != 0)
        return 8;
    return result;
}

static int wordexp_engine_wait_for_child(pid_t child, int *wait_status)
{
    pid_t waited;

    do {
        waited = waitpid(child, wait_status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child;
}

static int wordexp_engine_default_sigpipe_child(void)
{
    static const char source[] = "${" WORDEXP_ENGINE_UNSET ":?shown}";
    struct sigaction action;
    int diagnostics[2];
    int wait_status;
    pid_t child;

    if (pipe(diagnostics) != 0)
        return 0;
    /* Closing the sole read end before fork makes the raw-fd2 EPIPE
     * deterministic. The child inherits only the write end it redirects. */
    if (close(diagnostics[0]) != 0) {
        (void)close(diagnostics[1]);
        return 0;
    }
    child = fork();
    if (child < 0) {
        (void)close(diagnostics[1]);
        return 0;
    }
    if (child == 0) {
        wordexp_t words = { 0 };

        if (dup2(diagnostics[1], STDERR_FILENO) != STDERR_FILENO ||
            close(diagnostics[1]) != 0)
            _exit(120);
        memset(&action, 0, sizeof action);
        action.sa_handler = SIG_DFL;
        if (sigemptyset(&action.sa_mask) != 0 ||
            sigaction(SIGPIPE, &action, NULL) != 0)
            _exit(121);
        (void)wordexp(source, &words, WRDE_SHOWERR);
        wordexp_engine_discard(&words);
        _exit(122);
    }
    if (close(diagnostics[1]) != 0)
        return 0;
    if (!wordexp_engine_wait_for_child(child, &wait_status))
        return 0;
    if (WIFSIGNALED(wait_status) && WTERMSIG(wait_status) == SIGPIPE)
        return 1;
    /* The pinned source delegates its diagnostic to a shell child and returns
     * normally. Keep this exact exit sentinel separate from arbitrary exits. */
    if (WIFEXITED(wait_status) && WEXITSTATUS(wait_status) == 122)
        return 2;
    return 0;
}

static int wordexp_engine_ignored_sigpipe_append(void)
{
    static const char *const prior_words[] = { "prior-one", "prior-two" };
    static const char source[] = "${" WORDEXP_ENGINE_UNSET ":?shown}";
    struct wordexp_engine_record_snapshot snapshot;
    struct sigaction ignored;
    struct sigaction previous;
    int diagnostics[2] = { -1, -1 };
    int saved_stderr = -1;
    int signal_changed = 0;
    wordexp_t words = { 0 };
    int status;
    int saved_errno;
    int result = 0;

    words.we_offs = 2;
    if (wordexp("prior-one prior-two", &words, WRDE_DOOFFS) != 0 ||
        !wordexp_engine_check_complete(&words, 2, prior_words, 2) ||
        !wordexp_engine_snapshot_record(&words, &snapshot))
    {
        wordexp_engine_discard(&words);
        return 0;
    }
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0 || pipe(diagnostics) != 0)
        goto cleanup;
    memset(&ignored, 0, sizeof ignored);
    ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) != 0 ||
        sigaction(SIGPIPE, &ignored, &previous) != 0)
    {
        goto cleanup;
    }
    signal_changed = 1;
    if (dup2(diagnostics[1], STDERR_FILENO) != STDERR_FILENO ||
        close(diagnostics[1]) != 0 || close(diagnostics[0]) != 0)
    {
        goto cleanup;
    }
    diagnostics[0] = -1;
    diagnostics[1] = -1;
    errno = E2BIG;
    status = wordexp(source, &words,
        WRDE_DOOFFS | WRDE_APPEND | WRDE_SHOWERR);
    saved_errno = errno;
    if (dup2(saved_stderr, STDERR_FILENO) != STDERR_FILENO ||
        close(saved_stderr) != 0)
    {
        saved_stderr = -1;
        goto cleanup;
    }
    saved_stderr = -1;
    if (sigaction(SIGPIPE, &previous, NULL) != 0)
        goto cleanup;
    signal_changed = 0;
    result = status == WRDE_SYNTAX && saved_errno == E2BIG &&
        wordexp_engine_snapshot_is_unchanged(&words, &snapshot);

cleanup:
    if (diagnostics[0] >= 0)
        (void)close(diagnostics[0]);
    if (diagnostics[1] >= 0)
        (void)close(diagnostics[1]);
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        (void)close(saved_stderr);
    }
    if (signal_changed)
        (void)sigaction(SIGPIPE, &previous, NULL);
    if (!wordexp_engine_release(&words, 2))
        result = 0;
    return result;
}

/* This does not install a signal policy. It observes the ordinary inherited
 * default in a child, then restores the caller's complete SIGPIPE sigaction
 * after a separate ignored-disposition append call. */
static int wordexp_engine_sigpipe_case(void)
{
    struct wordexp_engine_environment_slot variable = { 0 };
    int child_result;
    int result = 1;

    if (wordexp_engine_save_environment(&variable, WORDEXP_ENGINE_UNSET) != 0)
        return 1;
    if (unsetenv(WORDEXP_ENGINE_UNSET) != 0) {
        result = 2;
        goto cleanup;
    }
    child_result = wordexp_engine_default_sigpipe_child();
    if (child_result == 2) {
        if (wordexp_engine_ignored_sigpipe_append())
            result = WORDEXP_ENGINE_SOURCE_RED_SIGPIPE;
        else
            result = 4;
        goto cleanup;
    }
    if (child_result != 1) {
        result = 3;
        goto cleanup;
    }
    if (!wordexp_engine_ignored_sigpipe_append()) {
        result = 4;
        goto cleanup;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup:
    if (wordexp_engine_restore_environment(&variable) != 0)
        return 5;
    return result;
}

/* Invalid multibyte bytes in C.UTF-8 patterns.
 *
 * musl's fnmatch treats an invalid multibyte pattern byte as UNMATCHABLE, and
 * its FNM_PATHNAME component scan never returns once it reaches one (the
 * `fnmatch-pathname-unmatchable` difference in owned-pattern.md). Word
 * expansion shares that matcher but never takes the FNM_PATHNAME path:
 * pathname expansion matches one component at a time and parameter removal
 * matches whole values. Each input therefore terminates in both runtimes,
 * leaves a pathname pattern literal, and never removes a prefix or suffix
 * through the invalid byte. Every call runs in a child under an alarm so a
 * nonterminating matcher is a failure instead of a cell timeout. */
static int wordexp_engine_invalid_multibyte_child(const char *source,
    const char *expected)
{
    wordexp_t words = { 0 };
    pid_t child;
    int status;

    if (fflush(stdout) != 0)
        return 0;
    child = fork();
    if (child < 0)
        return 0;
    if (child == 0) {
        int valid;

        alarm(10);
        valid = wordexp(source, &words, 0) == 0 &&
            wordexp_engine_check_complete(&words, 0, &expected, 1) &&
            wordexp_engine_release(&words, 0);
        _exit(valid ? 0 : 1);
    }
    return waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0;
}

static int wordexp_engine_invalid_multibyte_pattern_case(void)
{
    static const char *const sources[] = {
        "/\377*", "/*/\377", "\\\377*",
        "${" WORDEXP_ENGINE_INVALID "#\377}",
        "${" WORDEXP_ENGINE_INVALID "%\377*}",
        "${" WORDEXP_ENGINE_INVALID "##*\377}",
        "${" WORDEXP_ENGINE_INVALID_ONLY "#\377}",
        "${" WORDEXP_ENGINE_INVALID_ONLY "%?}",
    };
    static const char *const expected[] = {
        "/\377*", "/*/\377", "\377*", "a\377b", "a\377b", "a\377b", "\377",
        "\377",
    };
    struct wordexp_engine_environment_slot invalid = { 0 };
    struct wordexp_engine_environment_slot invalid_only = { 0 };
    size_t index;
    int result = 1;

    if (setlocale(LC_CTYPE, "C.UTF-8") == NULL)
        return 1;
    if (wordexp_engine_save_environment(&invalid, WORDEXP_ENGINE_INVALID) != 0 ||
        wordexp_engine_save_environment(&invalid_only,
            WORDEXP_ENGINE_INVALID_ONLY) != 0)
        goto cleanup;
    if (setenv(WORDEXP_ENGINE_INVALID, "a\377b", 1) != 0 ||
        setenv(WORDEXP_ENGINE_INVALID_ONLY, "\377", 1) != 0) {
        result = 2;
        goto cleanup;
    }
    for (index = 0; index < sizeof sources / sizeof sources[0]; ++index) {
        if (!wordexp_engine_invalid_multibyte_child(sources[index],
                expected[index])) {
            result = 3 + (int)index;
            goto cleanup;
        }
    }
    result = WORDEXP_ENGINE_PASS;
cleanup:
    if (wordexp_engine_restore_environment(&invalid_only) != 0 ||
        wordexp_engine_restore_environment(&invalid) != 0)
        return 12;
    return result;
}

#ifdef CRABC_WORDEXP_RESULT_PRIVATE_TEST
/* These are fixture-only controls from owned_wordexp_result_failure.rs. They
 * are intentionally absent from normal archives and are never declared by an
 * installed header. */
extern void __crabc_test_wordexp_result_budget(size_t successful_requests);
extern void __crabc_test_wordexp_result_unlimited(void);

static int wordexp_engine_sweep_fresh(
    const char *source,
    const char *const expected[],
    size_t expected_count,
    int flags,
    size_t offsets,
    int *saw_nospace,
    int *saw_success,
    int *saw_vector
)
{
    size_t budget;

    *saw_nospace = 0;
    *saw_success = 0;
    *saw_vector = 0;
    for (budget = 0; budget < WORDEXP_ENGINE_BUDGET_LIMIT; ++budget) {
        wordexp_t words = { 0 };
        int status;
        int saved_errno;
        int valid;
        int released;

        words.we_offs = offsets;
        __crabc_test_wordexp_result_budget(budget);
        errno = E2BIG;
        status = wordexp(source, &words, flags);
        saved_errno = errno;
        valid = ((status == 0 && words.we_wordc == expected_count) ||
            status == WRDE_NOSPACE) &&
            saved_errno == E2BIG &&
            wordexp_engine_check_prefix(&words, offsets, expected, expected_count);
        if (words.we_wordv != NULL)
            *saw_vector = 1;
        if (status == WRDE_NOSPACE)
            *saw_nospace = 1;
        if (status == 0 && words.we_wordc == expected_count)
            *saw_success = 1;
        /* Keep the finite budget active through wordfree: frees are never
         * refused, including the zero-budget fresh failure. */
        released = wordexp_engine_release(&words, offsets);
        __crabc_test_wordexp_result_unlimited();
        if (!valid || !released)
            return 0;
    }
    return 1;
}

static int wordexp_engine_sweep_append(
    const char *source,
    const char *const expected[],
    size_t expected_count,
    int *saw_nospace,
    int *saw_success
)
{
    static const char *const prior[] = { "prior" };
    size_t budget;

    *saw_nospace = 0;
    *saw_success = 0;
    for (budget = 0; budget < WORDEXP_ENGINE_BUDGET_LIMIT; ++budget) {
        wordexp_t words = { 0 };
        int status;
        int saved_errno;
        int valid;
        int released;

        words.we_offs = 3;
        __crabc_test_wordexp_result_unlimited();
        if (wordexp("prior", &words, WRDE_DOOFFS) != 0 ||
            !wordexp_engine_check_complete(&words, 3, prior, 1))
        {
            wordexp_engine_discard(&words);
            return 0;
        }
        __crabc_test_wordexp_result_budget(budget);
        errno = E2BIG;
        status = wordexp(source, &words, WRDE_DOOFFS | WRDE_APPEND);
        saved_errno = errno;
        valid = ((status == 0 && words.we_wordc == expected_count) ||
            status == WRDE_NOSPACE) &&
            saved_errno == E2BIG &&
            wordexp_engine_check_prefix(&words, 3, expected, expected_count);
        if (status == WRDE_NOSPACE)
            *saw_nospace = 1;
        if (status == 0 && words.we_wordc == expected_count)
            *saw_success = 1;
        released = wordexp_engine_release(&words, 3);
        __crabc_test_wordexp_result_unlimited();
        if (!valid || !released)
            return 0;
    }
    return 1;
}

static int wordexp_engine_command_failure_prefix(
    const struct wordexp_engine_marker_root *marker
)
{
    static const char source[] =
        "one two $(printf x >> \"$" WORDEXP_ENGINE_MARKER "\"; printf command)";
    static const char *const expected[] = { "one", "two", "command" };
    size_t budget;
    int saw_one_word_nospace = 0;
    int saw_success = 0;

    for (budget = 0; budget < WORDEXP_ENGINE_BUDGET_LIMIT; ++budget) {
        wordexp_t words = { 0 };
        int status;
        int saved_errno;
        int valid;
        int released;

        if (!wordexp_engine_clear_marker(marker))
            return 0;
        __crabc_test_wordexp_result_budget(budget);
        errno = E2BIG;
        status = wordexp(source, &words, 0);
        saved_errno = errno;
        valid = ((status == 0 && words.we_wordc == 3) ||
            status == WRDE_NOSPACE) &&
            saved_errno == E2BIG &&
            wordexp_engine_check_prefix(&words, 0, expected, 3);
        if (status == WRDE_NOSPACE && words.we_wordc == 1) {
            if (!wordexp_engine_marker_missing(marker))
                valid = 0;
            saw_one_word_nospace = 1;
        }
        if (status == 0 && words.we_wordc == 3) {
            if (!wordexp_engine_marker_is_one_x(marker))
                valid = 0;
            saw_success = 1;
        }
        released = wordexp_engine_release(&words, 0);
        __crabc_test_wordexp_result_unlimited();
        if (!valid || !released)
            return 0;
    }
    return saw_one_word_nospace && saw_success;
}

static int wordexp_engine_result_failure_case(void)
{
    static const char *const fresh[] = { "one", "two", "three" };
    static const char *const growth[] = {
        "one", "two", "three", "four", "five", "six", "seven",
        "eight", "nine", "ten", "eleven", "twelve", "thirteen"
    };
    static const char *const appended[] = {
        "prior", "one", "two", "three", "four", "five", "six",
        "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen"
    };
    struct wordexp_engine_environment_slot empty = { 0 };
    struct wordexp_engine_environment_slot marker_variable = { 0 };
    struct wordexp_engine_marker_root marker = { { 0 }, { 0 } };
    int saw_nospace;
    int saw_success;
    int saw_vector;
    int result = 1;

    __crabc_test_wordexp_result_unlimited();
    if (wordexp_engine_save_environment(&empty, WORDEXP_ENGINE_EMPTY) != 0 ||
        wordexp_engine_save_environment(&marker_variable, WORDEXP_ENGINE_MARKER) != 0)
    {
        result = 1;
        goto cleanup;
    }

    if (!wordexp_engine_sweep_fresh("one two three", fresh, 3, 0, 0,
            &saw_nospace, &saw_success, &saw_vector) ||
        !saw_nospace || !saw_success || !saw_vector)
    {
        result = 2;
        goto cleanup;
    }

    if (setenv(WORDEXP_ENGINE_EMPTY, "", 1) != 0 ||
        !wordexp_engine_sweep_fresh("$" WORDEXP_ENGINE_EMPTY, NULL, 0,
            WRDE_DOOFFS, 2, &saw_nospace, &saw_success, &saw_vector) ||
        !saw_nospace || !saw_success || !saw_vector)
    {
        result = 3;
        goto cleanup;
    }

    if (!wordexp_engine_sweep_fresh(
            "one two three four five six seven eight nine ten eleven twelve thirteen",
            growth, 13, 0, 0, &saw_nospace, &saw_success, &saw_vector) ||
        !saw_nospace || !saw_success || !saw_vector)
    {
        result = 4;
        goto cleanup;
    }

    if (!wordexp_engine_sweep_append(
            "one two three four five six seven eight nine ten eleven twelve thirteen",
            appended, 14, &saw_nospace, &saw_success) ||
        !saw_nospace || !saw_success)
    {
        result = 5;
        goto cleanup;
    }

    if (!wordexp_engine_prepare_marker(&marker) ||
        setenv(WORDEXP_ENGINE_MARKER, marker.marker, 1) != 0 ||
        !wordexp_engine_command_failure_prefix(&marker))
    {
        result = 6;
        goto cleanup;
    }
    result = WORDEXP_ENGINE_PASS;

cleanup:
    __crabc_test_wordexp_result_unlimited();
    if (wordexp_engine_remove_marker(&marker) != 0)
        result = 7;
    if (wordexp_engine_restore_environment(&marker_variable) != 0 ||
        wordexp_engine_restore_environment(&empty) != 0)
    {
        return 8;
    }
    return result;
}
#endif

static int wordexp_engine_emit_result(const char *name, int result)
{
    if (result == WORDEXP_ENGINE_PASS) {
        printf("owned-wordexp-engine-%s: PASS\n", name);
        return 0;
    }
    if (result == WORDEXP_ENGINE_SOURCE_RED_UNDEF) {
        printf("owned-wordexp-engine-%s: SOURCE-RED wrde-undef-untyped\n", name);
        return 0;
    }
    if (result == WORDEXP_ENGINE_SOURCE_RED_DIAGNOSTIC) {
        printf("owned-wordexp-engine-%s: SOURCE-RED shell-diagnostic-format\n", name);
        return 0;
    }
    if (result == WORDEXP_ENGINE_SOURCE_RED_QUIET_DIAGNOSTIC) {
        printf("owned-wordexp-engine-%s: SOURCE-RED quiet-shell-diagnostic\n",
            name);
        return 0;
    }
    if (result == WORDEXP_ENGINE_SOURCE_RED_NOCMD) {
        printf("owned-wordexp-engine-%s: SOURCE-RED nocmd-parameter-word-badchar\n",
            name);
        return 0;
    }
    if (result == WORDEXP_ENGINE_SOURCE_RED_SIGPIPE) {
        printf("owned-wordexp-engine-%s: SOURCE-RED shell-child-no-raw-sigpipe\n",
            name);
        return 0;
    }
    printf("owned-wordexp-engine-%s: FAIL %d\n", name, result);
    return 1;
}

/* The one-object receipt calls this directly after including the
 * file. The standalone main below has exactly the same selector surface. */
static int wordexp_engine_run_selector(const char *selector)
{
    if (strcmp(selector, "--engine-literals") == 0)
        return wordexp_engine_emit_result("literals", wordexp_engine_literals_case());
    if (strcmp(selector, "--engine-undef") == 0)
        return wordexp_engine_emit_result("undef", wordexp_engine_undef_case());
    if (strcmp(selector, "--engine-append-rollback") == 0)
        return wordexp_engine_emit_result("append-rollback",
            wordexp_engine_append_rollback_case());
    if (strcmp(selector, "--engine-reuse-offsets") == 0)
        return wordexp_engine_emit_result("reuse-offsets",
            wordexp_engine_reuse_offsets_case());
    if (strcmp(selector, "--engine-parameter-word") == 0)
        return wordexp_engine_emit_result("parameter-word",
            wordexp_engine_parameter_word_case());
    if (strcmp(selector, "--engine-diagnostics") == 0)
        return wordexp_engine_emit_result("diagnostics",
            wordexp_engine_diagnostics_case());
    if (strcmp(selector, "--engine-sigpipe") == 0)
        return wordexp_engine_emit_result("sigpipe", wordexp_engine_sigpipe_case());
    if (strcmp(selector, "--engine-invalid-multibyte-pattern") == 0)
        return wordexp_engine_emit_result("invalid-multibyte-pattern",
            wordexp_engine_invalid_multibyte_pattern_case());
#ifdef CRABC_WORDEXP_RESULT_PRIVATE_TEST
    if (strcmp(selector, "--engine-result-failure") == 0)
        return wordexp_engine_emit_result("result-failure",
            wordexp_engine_result_failure_case());
#endif
    printf("owned-wordexp-engine: FAIL unknown-selector\n");
    return 64;
}

#ifdef CRABC_WORDEXP_ENGINE_PROBE_MAIN
int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("owned-wordexp-engine: FAIL expected-one-selector\n");
        return 64;
    }
    return wordexp_engine_run_selector(argv[1]);
}
#endif
