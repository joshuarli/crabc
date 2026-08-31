#define _GNU_SOURCE 1
#include <dlfcn.h>

extern const unsigned char *dladdr_bounded_data_address(void);
extern const unsigned char *dladdr_bounded_interior_address(void);
extern const unsigned char *dladdr_bounded_gap_address(void);

static int text_equal(const char *left, const char *right) {
    if (left == 0 || right == 0) return 0;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static int contains(const char *text, const char *needle) {
    if (text == 0) return 0;
    for (unsigned long start = 0; text[start] != '\0'; ++start) {
        unsigned long offset = 0;
        while (needle[offset] != '\0' && text[start + offset] == needle[offset]) {
            ++offset;
        }
        if (needle[offset] == '\0') return 1;
    }
    return 0;
}

static int fields_are_clear(const Dl_info *information) {
    return information->dli_fname == 0 && information->dli_fbase == 0
        && information->dli_sname == 0 && information->dli_saddr == 0;
}

int main(void) {
#ifdef CRABC_DLADDR_SYMBOL_BOUNDS_UNAVAILABLE
    Dl_info unavailable = { (void *)1, (void *)1, (void *)1, (void *)1 };
    return dladdr((const void *)dladdr_bounded_data_address(), &unavailable) != 0
        || !fields_are_clear(&unavailable);
#else
    Dl_info exact = { 0 };
    const unsigned char *data = dladdr_bounded_data_address();
    if (dladdr((const void *)data, &exact) != 1
        || exact.dli_fname == 0 || exact.dli_fbase == 0
        || !contains(exact.dli_fname, "libleaf-dladdr-symbol-bounds.so")
        || !text_equal(exact.dli_sname, "dladdr_bounded_data")
        || exact.dli_saddr != (void *)data) {
        return 41;
    }

    Dl_info interior = { 0 };
    const unsigned char *inside = dladdr_bounded_interior_address();
    if (dladdr((const void *)inside, &interior) != 1
        || interior.dli_fbase != exact.dli_fbase
        || !text_equal(interior.dli_sname, "dladdr_bounded_data")
        || interior.dli_saddr != (void *)data) {
        return 42;
    }

    Dl_info gap = { 0 };
    const unsigned char *outside = dladdr_bounded_gap_address();
    if (dladdr((const void *)outside, &gap) != 1
        || gap.dli_fbase != exact.dli_fbase
        || !contains(gap.dli_fname, "libleaf-dladdr-symbol-bounds.so")
        || gap.dli_sname != 0 || gap.dli_saddr != 0) {
        return 43;
    }
    return 0;
#endif
}
