/*
 * Private callback-free consumer for the fixed x86 loader graph.
 *
 * These records deliberately mirror the useful copied fields of crabc's
 * RuntimeV1 loader facade without claiming that the fixed graph owns libc,
 * public dlfcn, arbitrary handles, or runtime graph mutation.
 */

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long usize;

enum { TEXT_CAPACITY = 256, FIXED_GRAPH_IMAGE_COUNT = 3 };

struct text_v1 {
    u16 len;
    u16 flags;
    unsigned char bytes[TEXT_CAPACITY];
};

struct image_v1 {
    void *image_base;
    const void *program_headers;
    u16 program_header_count;
    u16 reserved;
    u64 additions;
    u64 removals;
    usize tls_module;
    void *tls_data;
    struct text_v1 image_name;
};

struct address_v1 {
    void *image_base;
    void *symbol_address;
    struct text_v1 image_name;
    struct text_v1 symbol_name;
};

struct information_v1 {
    void *image_base;
    void *dynamic_address;
    struct text_v1 image_name;
};

typedef int (*snapshot_fn)(struct image_v1 *, usize, usize *, u64 *, struct text_v1 *);
typedef int (*address_fn)(const void *, struct address_v1 *, struct text_v1 *);
typedef int (*information_fn)(usize, struct information_v1 *, struct text_v1 *);

struct fixed_graph_introspection_v1 {
    u64 magic;
    u32 version;
    u32 abi_size;
    snapshot_fn snapshot;
    address_fn address;
    information_fn information;
};

extern const struct fixed_graph_introspection_v1 *crabc_fixed_graph_introspection_record(void);
extern int mid_value(void);
extern int mid_initializers_ran(void);
extern int *mid_leaf_data_address(void);

_Static_assert(sizeof(struct text_v1) == 260, "fixed text v1 layout");
_Static_assert(sizeof(struct image_v1) == 320, "fixed image v1 layout");
_Static_assert(sizeof(struct address_v1) == 536, "fixed address v1 layout");
_Static_assert(sizeof(struct information_v1) == 280, "fixed information v1 layout");
_Static_assert(sizeof(struct fixed_graph_introspection_v1) == 40, "fixed record v1 layout");

static usize cstr_len(const char *text) {
    usize length = 0;
    while (text[length] != '\0') ++length;
    return length;
}

static int bytes_equal(const unsigned char *left, const unsigned char *right, usize length) {
    for (usize index = 0; index < length; ++index) {
        if (left[index] != right[index]) return 0;
    }
    return 1;
}

static int text_equal_cstr(const struct text_v1 *text, const char *expected) {
    usize length = cstr_len(expected);
    return text->flags == 0 && text->len == length
        && bytes_equal(text->bytes, (const unsigned char *)expected, length);
}

static int text_equal_literal(const struct text_v1 *text, const char *expected) {
    return text_equal_cstr(text, expected);
}

static int fail(int code) {
    return code;
}

int main(int argc, char **argv) {
    if (argc < 1 || argv == (void *)0 || argv[0] == (void *)0) return fail(40);
    if (mid_value() != 42 || !mid_initializers_ran()) return fail(41);

    const struct fixed_graph_introspection_v1 *runtime = crabc_fixed_graph_introspection_record();
    if (runtime == (void *)0
        || runtime->magic != 0x43524142435f5849ul
        || runtime->version != 1
        || runtime->abi_size != sizeof(*runtime)
        || runtime->snapshot == (void *)0
        || runtime->address == (void *)0
        || runtime->information == (void *)0) {
        return fail(127);
    }

    struct image_v1 images[FIXED_GRAPH_IMAGE_COUNT];
    struct text_v1 error;
    usize count = 99;
    u64 generation = 99;
    if (runtime->snapshot(images, FIXED_GRAPH_IMAGE_COUNT - 1, &count, &generation, &error) != -1
        || count != 0 || generation != 0
        || !text_equal_literal(&error, "loader snapshot capacity is too small")) {
        return fail(42);
    }
    if (runtime->snapshot((void *)0, FIXED_GRAPH_IMAGE_COUNT, &count, &generation, &error) != -1
        || !text_equal_literal(&error, "loader snapshot output is invalid")) {
        return fail(43);
    }
    if (runtime->snapshot(images, FIXED_GRAPH_IMAGE_COUNT, &count, &generation, &error) != 0
        || count != FIXED_GRAPH_IMAGE_COUNT || generation != 0 || error.len != 0) {
        return fail(44);
    }

    if (!text_equal_cstr(&images[0].image_name, argv[0])
        || !text_equal_literal(&images[1].image_name, "libmid-introspection.so")
        || !text_equal_literal(&images[2].image_name, "libleaf-introspection.so")) {
        return fail(45);
    }
    for (usize index = 0; index < FIXED_GRAPH_IMAGE_COUNT; ++index) {
        if (images[index].image_base == (void *)0
            || images[index].program_headers == (void *)0
            || images[index].program_header_count == 0
            || images[index].reserved != 0
            || images[index].additions != 0
            || images[index].removals != 0
            || images[index].tls_module != 0
            || images[index].tls_data != (void *)0) {
            return fail(46);
        }
    }

    /* Caller mutations must not alias the loader's retained names. */
    images[1].image_name.bytes[0] = 'X';
    if (runtime->snapshot(images, FIXED_GRAPH_IMAGE_COUNT, &count, &generation, &error) != 0
        || !text_equal_literal(&images[1].image_name, "libmid-introspection.so")) {
        return fail(47);
    }

    struct address_v1 address;
    if (runtime->address((const void *)&mid_value, &address, &error) != 0
        || address.image_base != images[1].image_base
        || address.symbol_address != (void *)&mid_value
        || !text_equal_literal(&address.image_name, "libmid-introspection.so")
        || !text_equal_literal(&address.symbol_name, "mid_value")) {
        return fail(48);
    }
    int *leaf_data = mid_leaf_data_address();
    if (runtime->address((const void *)leaf_data, &address, &error) != 0
        || address.image_base != images[2].image_base
        || address.symbol_address != (void *)leaf_data
        || !text_equal_literal(&address.image_name, "libleaf-introspection.so")
        || !text_equal_literal(&address.symbol_name, "leaf_data")) {
        return fail(49);
    }
    if (runtime->address((const void *)&count, &address, &error) != -1
        || address.image_base != (void *)0 || address.symbol_address != (void *)0
        || address.image_name.len != 0 || address.symbol_name.len != 0
        || !text_equal_literal(&error, "loader address not found")) {
        return fail(50);
    }
    address.image_base = (void *)1;
    address.symbol_address = (void *)1;
    address.image_name.len = 99;
    address.symbol_name.len = 99;
    if (runtime->address((void *)0, &address, &error) != -1
        || address.image_base != (void *)0 || address.symbol_address != (void *)0
        || address.image_name.len != 0 || address.symbol_name.len != 0
        || !text_equal_literal(&error, "loader address lookup is invalid")) {
        return fail(54);
    }
    if (runtime->address((const void *)&mid_value, (void *)0, &error) != -1
        || !text_equal_literal(&error, "loader address lookup is invalid")) {
        return fail(55);
    }

    struct information_v1 information;
    for (usize index = 0; index < FIXED_GRAPH_IMAGE_COUNT; ++index) {
        if (runtime->information(index, &information, &error) != 0
            || information.image_base != images[index].image_base
            || information.dynamic_address == (void *)0
            || information.image_name.len != images[index].image_name.len
            || !bytes_equal(information.image_name.bytes, images[index].image_name.bytes,
                            images[index].image_name.len)) {
            return fail(51);
        }
    }
    if (runtime->information(FIXED_GRAPH_IMAGE_COUNT, &information, &error) != -1
        || information.image_base != (void *)0 || information.dynamic_address != (void *)0
        || information.image_name.len != 0
        || !text_equal_literal(&error, "loader information image is invalid")) {
        return fail(52);
    }
    if (runtime->information(0, (void *)0, &error) != -1
        || !text_equal_literal(&error, "loader information output is invalid")) {
        return fail(53);
    }

    return 0;
}
