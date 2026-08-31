/* Native Linux/x86-64 C++17 <regex.h> C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <regex.h>

using regcomp_signature = int (*)(regex_t *, const char *, int);
using regexec_signature = int (*)(const regex_t *, const char *, size_t,
    regmatch_t *, int);
using regerror_signature = size_t (*)(int, const regex_t *, char *, size_t);
using regfree_signature = void (*)(regex_t *);

regcomp_signature crabc_regex_regcomp = regcomp;
regexec_signature crabc_regex_regexec = regexec;
regerror_signature crabc_regex_regerror = regerror;
regfree_signature crabc_regex_regfree = regfree;
