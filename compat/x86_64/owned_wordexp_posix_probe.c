/* POSIX correction cells for the owned x86 wordexp workload.
 *
 * `owned_wordexp_probe.c` includes this file after its common word-vector
 * helpers.  Keeping these cases in a separately named C source makes the
 * source-oracle divergence searchable while the installed driver still emits
 * one ordinary C object and links those exact bytes to every oracle/product
 * mode.  The cases exercise only the public wordexp and unistd interfaces.
 */

#include <unistd.h>

#define WORDEXP_NOCMD_MARKER "/wordexp-nocmd-marker"

static int posix_check_words(const char *expression, const char *const expected[],
    size_t count)
{
    wordexp_t words = { 0 };

    if (wordexp(expression, &words, WRDE_NOCMD) != 0)
        return 1;
    if (!check_words(&words, count, expected)) {
        wordfree(&words);
        return 2;
    }
    return check_freed(&words) ? 0 : 3;
}

/* Capture the process stderr around the complete wordexp call.  The shell has
 * been reaped before this function restores fd 2, so the pipe's first read is
 * a finite observation of every diagnostic from the malformed source input. */
static int posix_quiet_case(void)
{
    int diagnostics[2] = { -1, -1 };
    int saved_stderr;
    int result;
    int saved_errno;
    char byte;
    ssize_t read_count;
    wordexp_t words = { 0 };

    if (pipe(diagnostics) != 0)
        return 1;
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stderr < 0) {
        close(diagnostics[0]);
        close(diagnostics[1]);
        return 2;
    }
    if (dup2(diagnostics[1], STDERR_FILENO) < 0) {
        close(saved_stderr);
        close(diagnostics[0]);
        close(diagnostics[1]);
        return 3;
    }
    close(diagnostics[1]);
    diagnostics[1] = -1;

    errno = ERANGE;
    result = wordexp("(", &words, 0);
    saved_errno = errno;

    if (dup2(saved_stderr, STDERR_FILENO) < 0) {
        close(saved_stderr);
        close(diagnostics[0]);
        wordfree(&words);
        return 5;
    }
    close(saved_stderr);
    read_count = read(diagnostics[0], &byte, 1);
    close(diagnostics[0]);

    if (result != WRDE_SYNTAX)
        return 6;
    if (words.we_wordc != 0 || words.we_wordv != NULL)
        return 7;
    if (saved_errno != ERANGE)
        return 8;
    if (read_count != 0)
        return 4;
    return 0;
}

static int posix_no_marker_command_case(const char *expression)
{
    wordexp_t words = { 0 };
    int result;

    if (unlink(WORDEXP_NOCMD_MARKER) != 0 && errno != ENOENT)
        return 1;
    result = wordexp(expression, &words, WRDE_NOCMD);
    if (access(WORDEXP_NOCMD_MARKER, F_OK) == 0) {
        wordfree(&words);
        return 4;
    }
    if (result != WRDE_CMDSUB) {
        wordfree(&words);
        return 2;
    }
    if (words.we_wordc != 0 || words.we_wordv != NULL)
        return 3;
    return errno == ENOENT ? 0 : 5;
}

/* An escaped dollar or opening brace is literal shell input. It must not turn
 * the rest of that unquoted text into a parameter-expansion context: doing so
 * would let a `WRDE_NOCMD` preflight miss a later shell control operator.
 * Keep this separate from the real nested-parameter marker cases below so a
 * failing public run identifies this exact boundary. */
static int posix_no_marker_badchar_case(const char *expression)
{
    wordexp_t words = { 0 };
    int result;

    if (unlink(WORDEXP_NOCMD_MARKER) != 0 && errno != ENOENT)
        return 1;
    result = wordexp(expression, &words, WRDE_NOCMD);
    if (access(WORDEXP_NOCMD_MARKER, F_OK) == 0) {
        wordfree(&words);
        return 4;
    }
    if (result != WRDE_BADCHAR) {
        wordfree(&words);
        return 2;
    }
    if (words.we_wordc != 0 || words.we_wordv != NULL)
        return 3;
    return errno == ENOENT ? 0 : 5;
}

static int posix_nocmd_escaped_brace_control_case(void)
{
    int result;

    result = posix_no_marker_badchar_case(
        "\\${ignored; printf marker > /wordexp-nocmd-marker; echo ignored}");
    if (result != 0)
        return result;
    result = posix_no_marker_badchar_case(
        "\\{ignored; printf marker > /wordexp-nocmd-marker; echo ignored}");
    if (result != 0)
        return result;
    return 0;
}

static int posix_nocmd_arithmetic_command_control_case(void)
{
    return posix_no_marker_command_case(
        "${U-$(( '$(printf marker > /wordexp-nocmd-marker)' ))}");
}

/* The substring-pattern variants have their own local quote context: the
 * enclosing double quote does not quote pattern characters. The final literal
 * brace deliberately balances a scanner that accidentally treats the quoted
 * `${` as a real child expansion, so an EOF-only depth check cannot hide the
 * command that follows the real outer expansion. */
static int posix_nocmd_pattern_control_case(void)
{
    return posix_no_marker_badchar_case(
        "\"${X#'${'}\"; printf marker > /wordexp-nocmd-marker; echo ignored}");
}

/* The nested parameter frame must suspend the outer arithmetic delimiter
 * count. The final quoted right parenthesis consumes a stale global count in
 * the broken scanner, leaving it apparently balanced after the marker runs. */
static int posix_nocmd_arithmetic_delimiter_control_case(void)
{
    return posix_no_marker_badchar_case(
        "$(( ${SET:-'('} )) ; printf marker > /wordexp-nocmd-marker; echo ')'");
}

/* Backslash-newline disappears before shell token recognition outside a
 * single-quoted string. The physical bytes below therefore form an active
 * `$(...)` command substitution, not a literal dollar followed by a slash. */
static int posix_nocmd_continuation_command_control_case(void)
{
    return posix_no_marker_command_case(
        "\"$\\\n(printf marker > /wordexp-nocmd-marker)\"");
}

/* POSIX dollar-single quoting is a distinct unquoted quote form. Its escaped
 * apostrophe does not end the quote; treating it as ordinary single quoting
 * would leave the final apostrophe open and hide the following top-level
 * separator from a lexical `WRDE_NOCMD` preflight. */
static int posix_nocmd_dollar_single_control_case(void)
{
    return posix_no_marker_badchar_case(
        "$'a\\'b'; printf marker > /wordexp-nocmd-marker; echo 'x'");
}

/* A comment starts only at a shell token boundary. Its quote-looking bytes are
 * not shell quotes: the physical newline ends the comment and makes the
 * following line active shell input. A lexical preflight that consumes the
 * quote bytes first can hide this command from WRDE_NOCMD. */
static int posix_nocmd_comment_control_case(void)
{
    return posix_no_marker_badchar_case(
        "# \"\n"
        "printf marker > /wordexp-nocmd-marker\n"
        "# \"");
}

/* `${10}` and the length forms are valid parameter syntax. Their values depend
 * on the controlled shell's positional arguments, so this public cell proves
 * only a successful lexical/public API path and deliberately does not turn
 * those fixture-specific values into a portable wordexp transcript. */
static int posix_nocmd_positional_case(void)
{
    wordexp_t words = { 0 };

    if (wordexp("${10}", &words, WRDE_NOCMD) != 0)
        return 1;
    if (!check_freed(&words))
        return 2;
    if (wordexp("${#1}", &words, WRDE_NOCMD) != 0)
        return 3;
    if (!check_freed(&words))
        return 4;
    if (wordexp("${#10}", &words, WRDE_NOCMD) != 0)
        return 5;
    return check_freed(&words) ? 0 : 6;
}

/* These are the bounded POSIX corrections, deliberately separate from the
 * fixed musl source-control cases in the including probe.  The scanner must
 * recognize only real, nested `${...}` parameter contexts: quoted or escaped
 * text stays literal, while unquoted naked braces and command substitutions
 * retain their existing error boundaries. */
static int posix_nocmd_case(void)
{
    static const char *const field[] = { "field" };
    static const char *const pair[] = { "left", "right" };
    static const char *const default_word[] = { "default" };
    static const char *const literal_open_brace[] = { "{" };
    static const char *const deeply_nested[] = { "end" };
    static const char *const arithmetic[] = { "5" };
    static const char *const literal_parameter[] = { "${FOO}" };
    static const char *const quoted_default[] = { "literal } text" };
    static const char *const closing_brace[] = { "}" };
    static const char *const dollar_single[] = { "a'b" };
    static const char *const semicolon_word[] = { "a;b" };
    static const char *const arithmetic_controls[] = { "3" };

    if (posix_check_words("${FOO}", field, 1) != 0)
        return 1;
    if (posix_check_words("${X} ${Y}", pair, 2) != 0)
        return 2;
    if (posix_check_words("${UNSET_X-${UNSET_Y-default}}", default_word, 1) != 0)
        return 3;
    if (unsetenv("WORDEXP_NOCMD_LITERAL_OPEN") != 0)
        return 4;
    /* POSIX parameter expansion closes on its matching right brace. An
     * opening brace in the parameter WORD is ordinary word text. */
    if (posix_check_words("${WORDEXP_NOCMD_LITERAL_OPEN-{}",
            literal_open_brace, 1) != 0)
        return 5;
    /* This crosses the scanner's inline frame storage and proves that valid
     * parameter nesting spills through the selected C allocator rather than
     * acquiring a private lexical depth limit. */
    if (posix_check_words("${U-${U-${U-${U-${U-${U-${U-${U-${U-end}}}}}}}}}",
            deeply_nested, 1) != 0)
        return 6;
    if (posix_check_words("$(( ${UNSET_X-2} + ${UNSET_Y-3} ))", arithmetic, 1) != 0)
        return 7;
    if (posix_check_words("$(( (1 << 1) | 1 ))", arithmetic_controls, 1) != 0 ||
        posix_check_words("$(( 7 & 3 ))", arithmetic_controls, 1) != 0 ||
        posix_check_words("$((1 +\n2))", arithmetic_controls, 1) != 0)
        return 8;
    if (posix_check_words("${UNSET_X-\"literal } text\"}", quoted_default, 1) != 0)
        return 9;
    if (posix_check_words("${U-'}'}", closing_brace, 1) != 0 ||
        posix_check_words("${U-\"}\"}", closing_brace, 1) != 0)
        return 10;
    if (posix_check_words("\"${U-a;b}\"", semicolon_word, 1) != 0 ||
        posix_check_words("${U-\"a;b\"}", semicolon_word, 1) != 0)
        return 11;

    if (posix_check_words("'${FOO}'", literal_parameter, 1) != 0)
        return 12;
    if (posix_check_words("\"\\${FOO}\"", literal_parameter, 1) != 0)
        return 13;
    if (posix_check_words("\\$\\{FOO\\}", literal_parameter, 1) != 0)
        return 14;
    if (posix_check_words("$'a\\'b'", dollar_single, 1) != 0)
        return 15;

    if (!check_initial_error("{", WRDE_NOCMD, WRDE_BADCHAR) ||
        !check_initial_error("}", WRDE_NOCMD, WRDE_BADCHAR) ||
        !check_initial_error("one; two", WRDE_NOCMD, WRDE_BADCHAR) ||
        !check_initial_error("$(echo x)", WRDE_NOCMD, WRDE_CMDSUB))
        return 16;

    if (posix_no_marker_command_case(
            "${UNSET_X-${UNSET_Y-$(printf marker > /wordexp-nocmd-marker)}}") != 0)
        return 17;
    if (posix_no_marker_command_case(
            "${UNSET_X-${UNSET_Y-default}}$(printf marker > /wordexp-nocmd-marker)") != 0)
        return 18;
    if (posix_no_marker_badchar_case(
            "{; printf marker > /wordexp-nocmd-marker") != 0)
        return 19;
    if (posix_no_marker_command_case(
            "${WORDEXP_NOCMD_LITERAL_OPEN-{}$(printf marker > /wordexp-nocmd-marker)") != 0)
        return 20;
    return 0;
}

/* This is intentionally a non-qualifying fixed-source observation. POSIX
 * WRDE_UNDEF remains unresolved for this batch; this mode records the fixed
 * musl behavior and is not used as a positive compatibility cell. */
static int posix_undef_source_observation(void)
{
    static const char *const no_words[] = { NULL };
    wordexp_t words = { 0 };

    if (wordexp("${WORDEXP_UNDEF_MISSING}", &words, WRDE_UNDEF) != 0)
        return 1;
    if (!check_words(&words, 0, no_words)) {
        wordfree(&words);
        return 2;
    }
    return check_freed(&words) ? 0 : 3;
}
