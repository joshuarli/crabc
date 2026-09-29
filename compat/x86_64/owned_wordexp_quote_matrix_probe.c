/* Bounded public-ABI expansion matrix. Each expression is fixed source text;
 * only the installed wordexp provider and the sealed shell fixture interpret it.
 * Fresh records start with hostile unused fields so accidental reads of caller
 * storage are visible without relying on an uninitialized C object. */

struct wordexp_quote_case {
    const char *expression;
    int flags;
    int status;
    size_t count;
    const char *first;
    const char *second;
};

static int wordexp_quote_matrix_case(void)
{
    static const struct wordexp_quote_case cases[] = {
        { "'a b'\"c d\"", 0, 0, 1, "a bc d", NULL },
        { "\"\"''", 0, 0, 1, "", NULL },
        { "left\\ right", 0, 0, 1, "left right", NULL },
        { "\"$CRABC_WORDEXP\"", 0, 0, 1, "bar baz", NULL },
        { "$CRABC_WORDEXP", WRDE_UNDEF, 0, 2, "bar", "baz" },
        { "'$CRABC_WORDEXP'", 0, 0, 1, "$CRABC_WORDEXP", NULL },
        { "$(printf %s hi)", 0, 0, 1, "hi", NULL },
        { "\"$(printf 'a b')\"", WRDE_SHOWERR, 0, 1, "a b", NULL },
        { "$((2+3*4))", WRDE_NOCMD, 0, 1, "14", NULL },
        { "${CRABC_WORDEXP_MISSING:-fallback}", 0, 0, 1, "fallback", NULL },
        { "${CRABC_WORDEXP_MISSING+skip}", 0, 0, 0, NULL, NULL },
        { "$(printf %s hi)", WRDE_NOCMD, WRDE_CMDSUB, 0, NULL, NULL },
    };
    size_t index;

    for (index = 0; index < sizeof cases / sizeof cases[0]; ++index) {
        const struct wordexp_quote_case *test = &cases[index];
        wordexp_t words = { .we_wordc = 37, .we_wordv = (char **)1,
            .we_offs = 19 };
        int status = wordexp(test->expression, &words, test->flags);

        if (status != test->status)
            return (int)(index * 4 + 1);
        if (status != 0)
            continue; /* C only promises a result record after success. */
        if (words.we_wordc != test->count || words.we_wordv == NULL)
            return (int)(index * 4 + 2);
        if ((test->count > 0 &&
                strcmp(words.we_wordv[0], test->first) != 0) ||
            (test->count > 1 &&
                strcmp(words.we_wordv[1], test->second) != 0) ||
            words.we_wordv[test->count] != NULL)
            return (int)(index * 4 + 3);
        wordfree(&words);
        if (words.we_wordv != NULL || words.we_wordc != 0)
            return (int)(index * 4 + 4);
    }

    /* DOOFFS is the one input field on a fresh call. The old vector/count
     * must be ignored; append keeps string ownership alive across its vector
     * replacement, and wordfree leaves the caller's offset for reuse. */
    {
        wordexp_t words = { .we_wordc = 37, .we_wordv = (char **)1,
            .we_offs = 2 };
        char *first;

        if (wordexp("'first word'", &words, WRDE_DOOFFS) != 0 ||
            words.we_offs != 2 || words.we_wordc != 1 ||
            words.we_wordv == NULL || words.we_wordv[0] != NULL ||
            words.we_wordv[1] != NULL ||
            strcmp(words.we_wordv[2], "first word") != 0 ||
            words.we_wordv[3] != NULL)
            return 50;
        first = words.we_wordv[2];
        if (wordexp("\"$CRABC_WORDEXP\"", &words,
                WRDE_DOOFFS | WRDE_APPEND) != 0 ||
            words.we_wordc != 2 || words.we_wordv == NULL ||
            words.we_wordv[2] != first ||
            strcmp(words.we_wordv[3], "bar baz") != 0 ||
            words.we_wordv[4] != NULL)
            return 51;
        wordfree(&words);
        if (words.we_wordv != NULL || words.we_wordc != 0 || words.we_offs != 2)
            return 52;
        wordfree(&words);
        if (words.we_wordv != NULL || words.we_wordc != 0 || words.we_offs != 2)
            return 53;
        if (wordexp("again", &words, WRDE_DOOFFS | WRDE_REUSE) != 0 ||
            words.we_wordc != 1 || words.we_wordv == NULL ||
            strcmp(words.we_wordv[2], "again") != 0)
            return 54;
        wordfree(&words);
    }
    return 0;
}
