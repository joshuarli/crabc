/* One installed-header regex object for musl and the owned x86 runtime. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <locale.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef REG_STARTEND
#error "REG_STARTEND is not part of musl's installed regex interface"
#endif

typedef int (*regcomp_signature)(regex_t *__restrict,
    const char *__restrict, int);
typedef int (*regexec_signature)(const regex_t *__restrict,
    const char *__restrict, size_t, regmatch_t *__restrict, int);
typedef void (*regfree_signature)(regex_t *);
typedef size_t (*regerror_signature)(int, const regex_t *__restrict,
    char *__restrict, size_t);

_Static_assert(sizeof(regoff_t) == sizeof(long),
    "installed x86 regoff_t is the signed LP64 long ABI");
_Static_assert(_Alignof(regoff_t) == _Alignof(long),
    "installed x86 regoff_t alignment");
_Static_assert((regoff_t)-1 < (regoff_t)0,
    "installed x86 regoff_t must remain signed");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regcomp),
    regcomp_signature), "installed regcomp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regexec),
    regexec_signature), "installed regexec declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regfree),
    regfree_signature), "installed regfree declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regerror),
    regerror_signature), "installed regerror declaration");

static regcomp_signature public_regcomp = regcomp;
static regexec_signature public_regexec = regexec;
static regfree_signature public_regfree = regfree;
static regerror_signature public_regerror = regerror;

static void fail(void) { _Exit(127); }
#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static void expect_match(const char *name, const char *pattern, int cflags,
    const char *text, size_t nmatch, const regmatch_t *expected,
    size_t expected_submatches)
{
    regex_t compiled;
    regmatch_t actual[4];
    size_t index;

    CHECK(nmatch <= sizeof actual / sizeof *actual);
    memset(actual, 0x5a, sizeof actual);
    CHECK(public_regcomp(&compiled, pattern, cflags) == REG_OK);
    CHECK(compiled.re_nsub == expected_submatches);
    CHECK(public_regexec(&compiled, text, nmatch, actual, 0) == REG_OK);
    for (index = 0; index != nmatch; ++index) {
        CHECK(actual[index].rm_so == expected[index].rm_so);
        CHECK(actual[index].rm_eo == expected[index].rm_eo);
    }
    printf("match %s nsub=%zu so=%ld eo=%ld\n", name, compiled.re_nsub,
        (long)actual[0].rm_so, (long)actual[0].rm_eo);
    public_regfree(&compiled);
}

static void expect_no_match(const char *name, const char *pattern, int cflags,
    const char *text, int eflags)
{
    regex_t compiled;

    CHECK(public_regcomp(&compiled, pattern, cflags) == REG_OK);
    CHECK(public_regexec(&compiled, text, 0, 0, eflags) == REG_NOMATCH);
    public_regfree(&compiled);
    printf("nomatch %s\n", name);
}

static void check_nosub(void)
{
    regex_t compiled;
    regmatch_t untouched = {71, 72};

    CHECK(public_regcomp(&compiled, "^abc$", REG_NOSUB) == REG_OK);
    CHECK(public_regexec(&compiled, "abc", 1, &untouched, 0) == REG_OK);
    CHECK(untouched.rm_so == 71 && untouched.rm_eo == 72);
    public_regfree(&compiled);
    puts("nosub-preserves-pmatch");
}

static void check_compile_and_free(void)
{
    regex_t compiled;
    regmatch_t actual[2];

    CHECK(public_regcomp(&compiled, "(ab|a)(b?)", REG_EXTENDED) == REG_OK);
    CHECK(compiled.re_nsub == 2);
    public_regfree(&compiled);

    /* `regfree` releases the completed TNFA graph.  A subsequent `regcomp`
     * overwrites the public output record before a new graph is exposed. */
    CHECK(public_regcomp(&compiled, "(a|b)+", REG_EXTENDED) == REG_OK);
    CHECK(public_regexec(&compiled, "zab", 2, actual, 0) == REG_OK);
    CHECK(actual[0].rm_so == 1 && actual[0].rm_eo == 3);
    CHECK(actual[1].rm_so == 2 && actual[1].rm_eo == 3);
    public_regfree(&compiled);
    puts("compile-regfree-recompile");
}

static void check_errors(void)
{
    regex_t compiled;
    char complete[32];
    char bounded[4];
    char unknown[14];

    CHECK(public_regcomp(&compiled, "[", REG_EXTENDED) == REG_EBRACK);
    CHECK(public_regerror(REG_EBRACK, 0, complete, sizeof complete) == 12);
    CHECK(!memcmp(complete, "Missing ']'", 11) && complete[11] == '\0');
    CHECK(public_regerror(REG_EBRACK, 0, bounded, sizeof bounded) == 12);
    CHECK(!memcmp(bounded, "Mis", 3) && bounded[3] == '\0');
    CHECK(public_regerror(-1, 0, unknown, sizeof unknown) == 14);
    CHECK(!memcmp(unknown, "Unknown error", 13) && unknown[13] == '\0');
    puts("regerror-table-and-truncation");
}

/*
 * Deterministic differential corpus.
 *
 * The directed cases above name individual contracts; this corpus checks that
 * the owned TRE port reproduces pinned musl across the whole selected grammar.
 * One fixed table and one fixed-seed generator produce BRE/ERE patterns from
 * atoms, brackets, classes, escapes, anchors, groups, alternation, bounded and
 * unbounded repetition, backreferences, hex escapes, malformed syntax, and
 * UTF-8/invalid bytes.  Each pattern is compiled with eight flag sets in both
 * the C and C.UTF-8 locales.  Every successful compilation is executed on
 * fixed and generated subjects with all four REG_NOTBOL/REG_NOTEOL
 * combinations, plus nmatch 0 and 1 calls.
 *
 * Each observation folds the compile status, `re_nsub` after success, and the
 * execute status plus all ten `regmatch_t` slots (sentinels included) into a
 * 64-bit FNV-1a digest.  The runner compares complete transcripts, so one
 * digest line per block localizes a divergence without retaining every row;
 * `--corpus-trace` prints each observation for diagnosis.  Undefined uses
 * (executing or freeing after a failed `regcomp`) are never exercised.
 */
/* Diagnostic builds may select another generator seed; evidence uses this. */
#ifndef CORPUS_SEED
#define CORPUS_SEED 0x9e3779b97f4a7c15ULL
#endif

enum {
    CORPUS_NMATCH = 10,
    CORPUS_RANDOM_PATTERNS = 2000,
    CORPUS_STRUCTURED_PATTERNS = 3000,
    CORPUS_BLOCK = 500,
};

static const char *const corpus_fixed_patterns[] = {
    "", "a", "abc", "a|b", "a\\|b", "(a|ab)(c|bcd)(d*)",
    "\\(a\\|ab\\)\\(c\\|bcd\\)\\(d*\\)", "(a*)*", "(a*)+", "(a|b)*c",
    "(a+|b+)*", "((a)|b)+", "(a)|b", "a(b)?c", "(.*)(.*)", "(.*)\\1",
    "\\(.*\\)\\1", "\\(a*\\)*\\1", "\\(a\\)\\(b\\)\\2\\1", "\\(\\(a\\)b\\)*\\2",
    "^\\(a\\)*$", "a\\{2,3\\}", "a{2,3}", "a{0}", "(a){0}b", "a{1,255}",
    "a{255}", "a{256}", "a{3,2}", "a{,}", "a{,2}", "a{1", "a\\{1", "x{2}{3}",
    "(ab){2}", "(a?){3}a{3}", "[[:alpha:]]+", "[[:alnum:]_]+",
    "[^[:space:]]+", "[a-zA-Z0-9]+", "[[:blank:]]", "[[:cntrl:]]",
    "[[:graph:]]+", "[[:print:]]+", "[[:xdigit:]]+", "[[:lower:]]",
    "[[:upper:]]", "[]-a]", "[^-]", "[\\]]", "[a-z--@]", "\\<a", "a\\>",
    "\\ba\\b", "\\Ba", "\\w+", "\\s*\\S+", "\\d\\D", "\\W", "^$", "^*a",
    "a**", "a*+", "a+*", "a+?", "(^a)", "(a$)", "a^b", "a$b", "\\(^a\\)",
    "\\(a$\\)", "a\\$", "$a", "x*y*z*", "(((((((((((a)))))))))))",
    "\\(\\(\\(\\(\\(\\(\\(\\(\\(\\(a\\)\\)\\)\\)\\)\\)\\)\\)\\)\\)\\9",
    "((a)|(b))*", "(a|)", "(|a)", "()", "a||b", "(*a)", "(+a)", "*a", "+a",
    "?a", "{1}a", "a|*b", "(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)", "\\(a\\)\\10",
    "[", "[]", "[^]", "[a-", "[[:alpha:]", "[[:alpha", "[[:foo:]]",
    "[[.a.]]", "[[=a=]]", "[c-a]", "(", ")", "a)", "\\(", "\\)", "a\\",
    "\\x", "\\x4", "\\x41", "\\x{e9}", "\\x{}", "\\x{110000}", "\\x{41",
    "\\n", "\\t", "\\{", "\\}", "\\\\", "\xc3\xa9+", "[\xc3\xa9]",
    "[^\xc3\xa9]x", "[\xc3\xa9-\xc3\xbf]+", ".\\{2\\}", "\xc3", "a\xff" "b",
    "[\xff]", "\\(a\\)*\\1*", "\\(ab*\\)*\\1", "(a|b)*(ab)", "(aa|a)(a|aa)",
    "(a*)(b|abc)(c*)", "(a.|.b)*", "\\(.\\)\\(.\\)\\2\\1", "a\\{0,\\}b",
    "a\\?b\\+", "[[:alpha:][:digit:]]", "[^[:alpha:][:digit:]]",
    "[^a[:upper:]]+", "[[:upper:]a-c]+", "(x|xy)(z|yz)", "(ab|a)(bc|c)?",
};

static const char *const corpus_tokens[] = {
    "a", "b", "c", "A", "B", "_", " ", "1", ".", "\\.", "\n",
    "\xc3\xa9", "\xff", "\xc3", "*", "+", "?", "{", "}", "{2}", "{1,}",
    "{0,2}", "{,2}", "{2,1}", "{256}", "\\{2\\}", "\\{1,\\}", "\\{0,1\\}",
    "\\+", "\\?", "\\*", "|", "\\|", "(", ")", "\\(", "\\)", "()", "\\(\\)",
    "(a)", "\\(a\\)", "^", "$", "\\^", "\\$", "[ab]", "[^a]", "[a-c]", "[]a]",
    "[^]a]", "[a-]", "[-a]", "[c-a]", "[a", "]", "[[:alpha:]]",
    "[[:digit:]]", "[[:space:]]", "[[:upper:]]", "[[:lower:]]",
    "[^[:alnum:]]", "[^[:upper:][:digit:]]", "[[:punct:]_]", "[[:foo:]]",
    "[[.a.]]", "[[=a=]]", "[\xc3\xa9-\xc3\xbf]", "[^\xc3\xa9]", "[a-z--@]",
    "\\w", "\\W", "\\s", "\\S", "\\d", "\\D", "\\<", "\\>", "\\b", "\\B",
    "\\1", "\\2", "\\3", "\\x41", "\\x{e9}", "\\x{110000}", "\\x{41", "\\n",
    "\\t", "\\",
};

static const char *const corpus_subject_atoms[] = {
    "a", "b", "c", "A", "B", "_", " ", "1", "\n", ".", "\xc3\xa9", "\xff",
    "\xc3", "x", "ab",
};

static const char *const corpus_fixed_subjects[] = {
    "", "a", "ab", "abcd", "aab\nba", "A_b 1", "\xc3\xa9\xc3\xa9x", "\xff\xc3",
    "ababab", "x\ny\n", "aaa", "xyz",
};

static const int corpus_cflags[] = {
    0, REG_EXTENDED, REG_ICASE, REG_EXTENDED | REG_ICASE, REG_NEWLINE,
    REG_EXTENDED | REG_NEWLINE, REG_EXTENDED | REG_NOSUB, REG_ICASE | REG_NEWLINE,
};

static const int corpus_ere_cflags[] = {
    REG_EXTENDED, REG_EXTENDED | REG_ICASE, REG_EXTENDED | REG_NEWLINE,
    REG_EXTENDED | REG_NOSUB,
};

static const int corpus_bre_cflags[] = {
    0, REG_ICASE, REG_NEWLINE, REG_ICASE | REG_NEWLINE,
};

static const int corpus_eflags[] = {
    0, REG_NOTBOL, REG_NOTEOL, REG_NOTBOL | REG_NOTEOL,
};

struct corpus_state {
    unsigned long long random;
    unsigned long long digest;
    int trace;
    unsigned long compiled;
    unsigned long compile_errors[16];
    unsigned long executions;
    unsigned long matches;
};

static unsigned corpus_next(struct corpus_state *state)
{
    unsigned long long x = state->random;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state->random = x;
    return (unsigned)((x * 0x2545f4914f6cdd1dULL) >> 32);
}

static void corpus_fold(struct corpus_state *state, long value)
{
    unsigned long long bits = (unsigned long long)value;
    int index;

    for (index = 0; index != 8; ++index) {
        state->digest ^= (bits >> (index * 8)) & 0xff;
        state->digest *= 0x100000001b3ULL;
    }
}

static void corpus_append(char *buffer, size_t capacity, size_t *length,
    const char *piece)
{
    size_t size = strlen(piece);

    CHECK(*length + size < capacity);
    memcpy(buffer + *length, piece, size);
    *length += size;
    buffer[*length] = '\0';
}

static void corpus_trace_bytes(const char *label, const char *bytes)
{
    const unsigned char *cursor = (const unsigned char *)bytes;

    printf(" %s=", label);
    if (!*cursor)
        printf("-");
    for (; *cursor; ++cursor)
        printf("%02x", *cursor);
}

static void corpus_execute(struct corpus_state *state, const regex_t *compiled,
    const char *subject, int eflags, size_t nmatch)
{
    regmatch_t matches[CORPUS_NMATCH];
    size_t index;
    int status;

    for (index = 0; index != CORPUS_NMATCH; ++index) {
        matches[index].rm_so = -7 - (regoff_t)index;
        matches[index].rm_eo = -70 - (regoff_t)index;
    }
    status = public_regexec(compiled, subject, nmatch, nmatch ? matches : 0,
        eflags);
    ++state->executions;
    if (status == REG_OK)
        ++state->matches;
    corpus_fold(state, status);
    for (index = 0; index != CORPUS_NMATCH; ++index) {
        corpus_fold(state, (long)matches[index].rm_so);
        corpus_fold(state, (long)matches[index].rm_eo);
    }
    if (state->trace > 1) {
        corpus_trace_bytes("subject", subject);
        printf(" e%d/n%zu:%d", eflags, nmatch, status);
        for (index = 0; index != CORPUS_NMATCH; ++index)
            printf(" %ld,%ld", (long)matches[index].rm_so,
                (long)matches[index].rm_eo);
    }
}

static void corpus_pattern(struct corpus_state *state, const char *pattern,
    const int *cflags, size_t cflag_count)
{
    char subjects[3][64];
    size_t count;
    size_t index;
    size_t flag;
    size_t atom;

    for (index = 0; index != 3; ++index) {
        size_t length = 0;
        subjects[index][0] = '\0';
        count = corpus_next(state) % 9;
        for (atom = 0; atom != count; ++atom)
            corpus_append(subjects[index], sizeof subjects[index], &length,
                corpus_subject_atoms[corpus_next(state) %
                    (sizeof corpus_subject_atoms / sizeof *corpus_subject_atoms)]);
    }

    for (flag = 0; flag != cflag_count; ++flag) {
        regex_t compiled;
        int status;
        size_t subject;
        size_t eflag;

        memset(&compiled, 0x5a, sizeof compiled);
        status = public_regcomp(&compiled, pattern, cflags[flag]);
        corpus_fold(state, status);
        if (state->trace) {
            printf("corpus-trace");
            corpus_trace_bytes("pattern", pattern);
            printf(" c%d:%d", cflags[flag], status);
        }
        if (status != REG_OK) {
            CHECK(status > 0 && status < 16);
            ++state->compile_errors[status];
            if (state->trace)
                putchar('\n');
            continue;
        }
        ++state->compiled;
        corpus_fold(state, (long)compiled.re_nsub);
        if (state->trace)
            printf(" nsub=%zu", compiled.re_nsub);
        for (subject = 0; subject != sizeof corpus_fixed_subjects /
                sizeof *corpus_fixed_subjects + 3; ++subject) {
            const char *text = subject < sizeof corpus_fixed_subjects /
                sizeof *corpus_fixed_subjects ? corpus_fixed_subjects[subject]
                : subjects[subject - sizeof corpus_fixed_subjects /
                    sizeof *corpus_fixed_subjects];
            for (eflag = 0; eflag != sizeof corpus_eflags / sizeof *corpus_eflags;
                    ++eflag)
                corpus_execute(state, &compiled, text, corpus_eflags[eflag],
                    CORPUS_NMATCH);
        }
        corpus_execute(state, &compiled, corpus_fixed_subjects[4], 0, 0);
        corpus_execute(state, &compiled, corpus_fixed_subjects[4], 0, 1);
        if (state->trace)
            printf(" digest=%016llx\n", state->digest);
        public_regfree(&compiled);
    }
}

/*
 * Structured generator: syntactically valid nested expressions exercise
 * submatch tag ordering and, through BRE backreferences, the backtracking
 * executor far more often than the token soup above.  The same tree is
 * spelled once as an ERE and once as a BRE (including `\|`, `\+`, `\?`
 * and backreferences to already opened groups).
 */
struct corpus_builder {
    char ere[1024];
    char bre[1024];
    size_t ere_length;
    size_t bre_length;
    int groups;
    int backreferences;
    int closed[16];
    int closed_count;
};

static void corpus_emit(struct corpus_builder *builder, const char *ere,
    const char *bre)
{
    corpus_append(builder->ere, sizeof builder->ere, &builder->ere_length, ere);
    corpus_append(builder->bre, sizeof builder->bre, &builder->bre_length, bre);
}

static void corpus_expression(struct corpus_state *state,
    struct corpus_builder *builder, int depth);

/* A pattern either may contain BRE backreferences, and then uses only finite
 * quantifiers, or has no backreference and may use every quantifier.  Any
 * backreference selects the source backtracking executor for the whole
 * expression; unbounded (and especially nested) repetition then makes both
 * musl and the port exponential, which would measure the fixture timeout
 * instead of semantics.  A backreference names only an already closed group:
 * POSIX defines `\n` for a preceding subexpression, and musl's handling of a
 * reference into a still-open group is the documented intentional difference
 * in docs/evidence/x86-owned-regex.md. */
static void corpus_piece(struct corpus_state *state,
    struct corpus_builder *builder, int depth)
{
    static const char *const literals[] = {
        "a", "b", "c", "A", "\xc3\xa9", ".", "[ab]", "[^a]", "[[:alpha:]]",
        "[^[:space:]b]", "[a-c]", "_",
    };
    static const char *const assertions[] = {
        "^", "$", "\\<", "\\>", "\\b", "\\B", "\\w", "\\W",
    };
    static const char *const ere_quantifiers[] = {
        "*", "+", "?", "{2}", "{1,}", "{0,2}", "{1,3}", "{0}",
    };
    static const char *const bre_quantifiers[] = {
        "*", "\\+", "\\?", "\\{2\\}", "\\{1,\\}", "\\{0,2\\}",
        "\\{1,3\\}", "\\{0\\}",
    };
    static const unsigned finite_quantifiers[] = {2, 3, 5, 6, 7};
    unsigned choice = corpus_next(state) % (depth < 2 ? 16 : 12);
    unsigned quantifier;

    if (choice < 8) {
        const char *literal = literals[corpus_next(state) %
            (sizeof literals / sizeof *literals)];
        corpus_emit(builder, literal, literal);
    } else if (choice < 10) {
        const char *assertion = assertions[corpus_next(state) %
            (sizeof assertions / sizeof *assertions)];
        corpus_emit(builder, assertion, assertion);
    } else if (choice < 12) {
        int group = builder->closed_count ? builder->closed[corpus_next(state) %
            (unsigned)builder->closed_count] : 0;

        if (builder->backreferences && group && group <= 9) {
            char reference[3] = {'\\', 0, 0};
            reference[1] = (char)('0' + group);
            corpus_emit(builder, "b", reference);
        } else {
            corpus_emit(builder, "a", "a");
        }
    } else {
        int group = ++builder->groups;

        corpus_emit(builder, "(", "\\(");
        corpus_expression(state, builder, depth + 1);
        corpus_emit(builder, ")", "\\)");
        if (builder->closed_count != (int)(sizeof builder->closed /
                sizeof *builder->closed))
            builder->closed[builder->closed_count++] = group;
    }
    quantifier = corpus_next(state) % 16;
    if (builder->backreferences)
        quantifier = quantifier < sizeof finite_quantifiers /
            sizeof *finite_quantifiers ? finite_quantifiers[quantifier] : 16;
    if (quantifier < sizeof ere_quantifiers / sizeof *ere_quantifiers)
        corpus_emit(builder, ere_quantifiers[quantifier],
            bre_quantifiers[quantifier]);
}

static void corpus_expression(struct corpus_state *state,
    struct corpus_builder *builder, int depth)
{
    unsigned branches = 1 + corpus_next(state) % 2;
    unsigned branch;

    for (branch = 0; branch != branches; ++branch) {
        unsigned pieces = 1 + corpus_next(state) % 3;
        unsigned piece;

        if (branch)
            corpus_emit(builder, "|", "\\|");
        for (piece = 0; piece != pieces; ++piece)
            corpus_piece(state, builder, depth);
    }
}

static void corpus_block(struct corpus_state *state, const char *locale,
    const char *kind, size_t block)
{
    printf("corpus locale=%s %s-block=%zu digest=%016llx\n", locale, kind,
        block, state->digest);
    state->digest = 0xcbf29ce484222325ULL;
}

/* Long subjects keep offsets and executor state beyond the short corpus. */
static void corpus_long_subjects(struct corpus_state *state)
{
    static const char *const ere[] = {
        "(a|b)*c", "(.*)(.*)x", "[[:alpha:]]+$", "a{1,255}", "(a|ab)*(b|ba)",
        "^(ab|a)*$", "(a*)(a*)b",
    };
    static const char *const bre[] = {
        "\\(a*\\)\\1$", "\\(ab*\\)*\\1", "^\\(.\\)\\(.*\\)\\1$",
    };
    static const int ere_flags[] = {REG_EXTENDED};
    static const int bre_flags[] = {0};
    static char subject[2049];
    size_t index;
    size_t length;

    for (length = 1; length <= 2048; length *= 8) {
        for (index = 0; index != length; ++index)
            subject[index] = "ab"[(index * 7 + length) % 5 == 0];
        subject[length] = '\0';
        for (index = 0; index != sizeof ere / sizeof *ere; ++index) {
            regex_t compiled;
            size_t eflag;
            int status = public_regcomp(&compiled, ere[index], ere_flags[0]);

            CHECK(status == REG_OK);
            for (eflag = 0; eflag != sizeof corpus_eflags / sizeof *corpus_eflags;
                    ++eflag)
                corpus_execute(state, &compiled, subject, corpus_eflags[eflag],
                    CORPUS_NMATCH);
            public_regfree(&compiled);
        }
        if (length > 256)
            continue;
        for (index = 0; index != sizeof bre / sizeof *bre; ++index) {
            regex_t compiled;
            int status = public_regcomp(&compiled, bre[index], bre_flags[0]);

            CHECK(status == REG_OK);
            corpus_execute(state, &compiled, subject, 0, CORPUS_NMATCH);
            public_regfree(&compiled);
        }
    }
    if (state->trace > 1)
        putchar('\n');
}

static void run_corpus(const char *locale, int trace)
{
    struct corpus_state state;
    char pattern[256];
    size_t index;
    size_t code;

    CHECK(setlocale(LC_ALL, locale) != NULL);
    memset(&state, 0, sizeof state);
    state.random = CORPUS_SEED;
    state.digest = 0xcbf29ce484222325ULL;
    state.trace = trace;
    for (index = 0; index != sizeof corpus_fixed_patterns /
            sizeof *corpus_fixed_patterns; ++index)
        corpus_pattern(&state, corpus_fixed_patterns[index], corpus_cflags,
            sizeof corpus_cflags / sizeof *corpus_cflags);
    corpus_block(&state, locale, "fixed", 0);
    corpus_long_subjects(&state);
    corpus_block(&state, locale, "long", 0);
    for (index = 0; index != CORPUS_STRUCTURED_PATTERNS; ++index) {
        struct corpus_builder builder;

        memset(&builder, 0, sizeof builder);
        builder.backreferences = index & 1;
        corpus_expression(&state, &builder, 0);
        corpus_pattern(&state, builder.ere, corpus_ere_cflags,
            sizeof corpus_ere_cflags / sizeof *corpus_ere_cflags);
        corpus_pattern(&state, builder.bre, corpus_bre_cflags,
            sizeof corpus_bre_cflags / sizeof *corpus_bre_cflags);
        if ((index + 1) % CORPUS_BLOCK == 0)
            corpus_block(&state, locale, "structured", index / CORPUS_BLOCK);
    }
    for (index = 0; index != CORPUS_RANDOM_PATTERNS; ++index) {
        size_t length = 0;
        size_t tokens = 1 + corpus_next(&state) % 8;
        size_t token;

        pattern[0] = '\0';
        for (token = 0; token != tokens; ++token)
            corpus_append(pattern, sizeof pattern, &length,
                corpus_tokens[corpus_next(&state) %
                    (sizeof corpus_tokens / sizeof *corpus_tokens)]);
        corpus_pattern(&state, pattern, corpus_cflags,
            sizeof corpus_cflags / sizeof *corpus_cflags);
        if ((index + 1) % CORPUS_BLOCK == 0)
            corpus_block(&state, locale, "random", index / CORPUS_BLOCK);
    }
    printf("corpus locale=%s compiled=%lu executions=%lu matches=%lu errors=",
        locale, state.compiled, state.executions, state.matches);
    for (code = 1; code != 16; ++code)
        printf("%s%lu", code == 1 ? "" : ",", state.compile_errors[code]);
    putchar('\n');
}

static void check_regerror_table(void)
{
    static const size_t sizes[] = {0, 1, 2, 9, 64};
    regex_t compiled;
    int code;
    size_t size;
    unsigned long long digest = 0xcbf29ce484222325ULL;

    CHECK(public_regcomp(&compiled, "(a)", REG_EXTENDED) == REG_OK);
    for (code = -3; code != 20; ++code) {
        for (size = 0; size != sizeof sizes / sizeof *sizes; ++size) {
            char buffer[64];
            size_t result;
            size_t index;

            memset(buffer, 0x7e, sizeof buffer);
            result = public_regerror(code, size & 1 ? &compiled : 0,
                sizes[size] ? buffer : 0, sizes[size]);
            for (index = 0; index != sizeof buffer; ++index) {
                digest ^= (unsigned char)buffer[index];
                digest *= 0x100000001b3ULL;
            }
            digest ^= result;
            digest *= 0x100000001b3ULL;
            if (sizes[size] == 64)
                printf("regerror code=%d size=%zu text=%s\n", code, result,
                    buffer);
        }
    }
    public_regfree(&compiled);
    printf("regerror-bounded digest=%016llx\n", digest);
}

int main(int argc, char **argv)
{
    int trace = 0;
    static const regmatch_t longest[] = {{1, 3}};
    static const regmatch_t captures[] = {{1, 3}, {2, 3}};
    static const regmatch_t backreference[] = {{1, 3}, {1, 2}};
    static const regmatch_t empty_backreference[] = {{0, 0}, {0, 0}};
    static const regmatch_t newline_anchor[] = {{0, 1}};
    static const regmatch_t class_match[] = {{2, 4}};
    static const regmatch_t icase_match[] = {{0, 1}};
    static const char utf8_text[] = {
        'z', (char)0xc3, (char)0xa9, (char)0xc3, (char)0xa9, 'x', '\0',
    };
    static const char utf8_pattern[] = {(char)0xc3, (char)0xa9, '+', '\0'};
    static const regmatch_t utf8_match[] = {{1, 5}};
    /* When a later path reaches the final state and wins the tag order, the
     * published match tags are the winner's, not the displaced path's. */
    static const regmatch_t final_winner[] = {{0, 2}, {0, 2}, {2, 2}};
    static const regmatch_t alternation_winner[] = {{0, 3}, {0, 2}, {2, 3}};
    /* An unknown escape reaches the ordinary literal parser, including its
     * REG_ICASE case pairing. */
    static const regmatch_t escaped_icase[] = {{1, 2}};

    CHECK(setlocale(LC_ALL, "C.UTF-8") != NULL);
    expect_match("ere-leftmost-longest", "a|ab", REG_EXTENDED, "zab", 1,
        longest, 0);
    expect_match("ere-captures", "(a|b)+", REG_EXTENDED, "zab", 2,
        captures, 1);
    expect_match("bre-backreference", "\\(a\\)\\1", 0, "zaa", 2,
        backreference, 1);
    expect_match("bre-empty-backreference", "\\(a*\\)\\1", 0, "", 2,
        empty_backreference, 1);
    expect_match("newline-anchor", "^a$", REG_EXTENDED | REG_NEWLINE,
        "a\nx", 1, newline_anchor, 0);
    expect_match("negated-class", "[^[:digit:]]+", REG_EXTENDED, "10xy2", 1,
        class_match, 0);
    expect_match("icase", "[a]", REG_EXTENDED | REG_ICASE, "A", 1,
        icase_match, 0);
    expect_match("utf8-byte-offsets", utf8_pattern, REG_EXTENDED, utf8_text, 1,
        utf8_match, 0);
    expect_match("ere-final-tag-winner", "(.*)(.*)", REG_EXTENDED, "ab", 3,
        final_winner, 2);
    expect_match("ere-final-alternation-winner", "(x|xy)(z|yz)", REG_EXTENDED,
        "xyz", 3, alternation_winner, 2);
    expect_match("bre-icase-escaped-literal", "\\A", REG_ICASE, "xa", 1,
        escaped_icase, 0);
    expect_match("ere-icase-escaped-literal", "\\A", REG_EXTENDED | REG_ICASE,
        "xa", 1, escaped_icase, 0);
    expect_no_match("notbol", "^a", REG_EXTENDED, "a", REG_NOTBOL);
    expect_no_match("noteol", "a$", REG_EXTENDED, "a", REG_NOTEOL);
    check_nosub();
    check_compile_and_free();
    check_errors();
    check_regerror_table();
    /* `--corpus-trace` prints one running digest per compilation;
     * `--corpus-trace-subjects` adds every execution observation. */
    if (argc == 2 && !strcmp(argv[1], "--corpus-trace"))
        trace = 1;
    else if (argc == 2 && !strcmp(argv[1], "--corpus-trace-subjects"))
        trace = 2;
    else
        CHECK(argc == 1);
    run_corpus("C", trace);
    run_corpus("C.UTF-8", trace);
    puts("owned-regex-installed-header-ok");
    return 0;
}
