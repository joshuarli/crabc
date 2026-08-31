/*
 * RuntimeV1-shaped dlfcn consumer for the immutable three-object x86 graph.
 * Every result is either an opaque loader token, an address in a retained
 * mapping, or caller-owned copied metadata. There is no ambient libc ABI.
 */

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned long usize;

enum {
    TEXT_CAPACITY = 256,
    FIXED_GRAPH_IMAGE_COUNT = 3,
    RTLD_LAZY_PRIVATE = 1,
    RTLD_NOW_PRIVATE = 2,
    RTLD_GLOBAL_PRIVATE = 0x100,
};

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

typedef int (*open_fn)(const unsigned char *, int, void **, struct text_v1 *);
typedef int (*symbol_fn)(void *, const unsigned char *, void **, struct text_v1 *);
typedef int (*close_fn)(void *, struct text_v1 *);
typedef int (*address_fn)(const void *, struct address_v1 *, struct text_v1 *);
typedef int (*snapshot_fn)(struct image_v1 *, usize, usize *, u64 *, struct text_v1 *);
typedef int (*information_fn)(void *, struct information_v1 *, struct text_v1 *);

struct fixed_graph_dlfcn_v1 {
    u64 magic;
    u32 version;
    u32 abi_size;
    open_fn open;
    symbol_fn symbol;
    close_fn close;
    address_fn address;
    snapshot_fn snapshot;
    information_fn information;
};

extern const struct fixed_graph_dlfcn_v1 *crabc_fixed_graph_dlfcn_record(void);
extern int mid_value(void);
extern int mid_initializers_ran(void);
extern int *mid_leaf_data_address(void);

_Static_assert(sizeof(struct text_v1) == 260, "fixed text v1 layout");
_Static_assert(sizeof(struct image_v1) == 320, "fixed image v1 layout");
_Static_assert(sizeof(struct address_v1) == 536, "fixed address v1 layout");
_Static_assert(sizeof(struct information_v1) == 280, "fixed information v1 layout");
_Static_assert(sizeof(struct fixed_graph_dlfcn_v1) == 64, "fixed dlfcn v1 layout");

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

static int text_equal(const struct text_v1 *text, const char *expected) {
    usize length = cstr_len(expected);
    return text->flags == 0 && text->len == length
        && bytes_equal(text->bytes, (const unsigned char *)expected, length);
}

static int fail(int code) {
    return code;
}

int main(int argc, char **argv) {
    if (argc < 1 || argv == (void *)0 || argv[0] == (void *)0) return fail(30);
    if (mid_value() != 42 || !mid_initializers_ran()) return fail(31);

    const struct fixed_graph_dlfcn_v1 *runtime = crabc_fixed_graph_dlfcn_record();
    if (runtime == (void *)0
        || runtime->magic != 0x43524142435f5844ul
        || runtime->version != 1
        || runtime->abi_size != sizeof(*runtime)
        || runtime->open == (void *)0
        || runtime->symbol == (void *)0
        || runtime->close == (void *)0
        || runtime->address == (void *)0
        || runtime->snapshot == (void *)0
        || runtime->information == (void *)0) {
        return fail(127);
    }

    struct text_v1 error;
    void *handle = (void *)1;
    if (runtime->open((const unsigned char *)"libmid-dlfcn.so", RTLD_NOW_PRIVATE,
                      (void *)0, &error) != -1
        || !text_equal(&error, "loader open output is invalid")) {
        return fail(32);
    }
    if (runtime->open((const unsigned char *)"libmid-dlfcn.so", 0, &handle, &error) != -1
        || handle != (void *)0 || !text_equal(&error, "loader open flags are invalid")) {
        return fail(33);
    }
    if (runtime->open((const unsigned char *)"libmid-dlfcn.so",
                      RTLD_NOW_PRIVATE | RTLD_GLOBAL_PRIVATE, &handle, &error) != -1
        || handle != (void *)0
        || !text_equal(&error, "fixed graph cannot promote global scope")) {
        return fail(34);
    }
    if (runtime->open((const unsigned char *)"/tmp/libmid-dlfcn.so", RTLD_NOW_PRIVATE,
                      &handle, &error) != -1
        || handle != (void *)0
        || !text_equal(&error, "fixed graph object is not already loaded")) {
        return fail(35);
    }

    void *main_handle;
    if (runtime->open((void *)0, RTLD_LAZY_PRIVATE, &main_handle, &error) != 0
        || main_handle == (void *)0 || error.len != 0) {
        return fail(36);
    }
    void *mid_handle_one;
    void *mid_handle_two;
    void *leaf_handle;
    if (runtime->open((const unsigned char *)"libmid-dlfcn.so", RTLD_NOW_PRIVATE,
                      &mid_handle_one, &error) != 0
        || runtime->open((const unsigned char *)"libmid-dlfcn.so", RTLD_LAZY_PRIVATE,
                         &mid_handle_two, &error) != 0
        || mid_handle_one == (void *)0 || mid_handle_one != mid_handle_two
        || runtime->open((const unsigned char *)"libleaf-dlfcn.so", RTLD_NOW_PRIVATE,
                         &leaf_handle, &error) != 0
        || leaf_handle == (void *)0 || leaf_handle == mid_handle_one) {
        return fail(37);
    }

    struct image_v1 images[FIXED_GRAPH_IMAGE_COUNT];
    usize count = 0;
    u64 generation = 99;
    if (runtime->snapshot(images, FIXED_GRAPH_IMAGE_COUNT, &count, &generation, &error) != 0
        || count != FIXED_GRAPH_IMAGE_COUNT || generation != 0 || error.len != 0
        || !text_equal(&images[0].image_name, argv[0])
        || !text_equal(&images[1].image_name, "libmid-dlfcn.so")
        || !text_equal(&images[2].image_name, "libleaf-dlfcn.so")) {
        return fail(38);
    }

    struct information_v1 information;
    if (runtime->information(main_handle, &information, &error) != 0
        || information.image_base != images[0].image_base
        || !text_equal(&information.image_name, argv[0])
        || runtime->information(mid_handle_one, &information, &error) != 0
        || information.image_base != images[1].image_base
        || information.dynamic_address == (void *)0
        || !text_equal(&information.image_name, "libmid-dlfcn.so")) {
        return fail(39);
    }

    void *mid_symbol = (void *)1;
    if (runtime->symbol(mid_handle_one, (const unsigned char *)"mid_value",
                        &mid_symbol, &error) != 0
        || mid_symbol != (void *)&mid_value || ((int (*)(void))mid_symbol)() != 42) {
        return fail(40);
    }
    void *main_symbol;
    if (runtime->symbol(main_handle, (const unsigned char *)"mid_value",
                        &main_symbol, &error) != 0
        || main_symbol != mid_symbol) {
        return fail(41);
    }
    void *leaf_symbol;
    if (runtime->symbol(mid_handle_one, (const unsigned char *)"leaf_data",
                        &leaf_symbol, &error) != 0
        || leaf_symbol != (void *)mid_leaf_data_address()
        || runtime->symbol(leaf_handle, (const unsigned char *)"leaf_data",
                           &handle, &error) != 0
        || handle != leaf_symbol) {
        return fail(42);
    }
    handle = (void *)1;
    if (runtime->symbol(leaf_handle, (const unsigned char *)"mid_value", &handle, &error) != -1
        || handle != (void *)0
        || !text_equal(&error, "symbol not found in fixed handle scope")) {
        return fail(43);
    }
    error.bytes[0] = 'X';
    if (runtime->symbol(leaf_handle, (const unsigned char *)"mid_value", &handle, &error) != -1
        || !text_equal(&error, "symbol not found in fixed handle scope")) {
        return fail(44);
    }

    struct address_v1 address;
    if (runtime->address(mid_symbol, &address, &error) != 0
        || address.image_base != images[1].image_base
        || address.symbol_address != mid_symbol
        || !text_equal(&address.image_name, "libmid-dlfcn.so")
        || !text_equal(&address.symbol_name, "mid_value")
        || runtime->address(leaf_symbol, &address, &error) != 0
        || address.image_base != images[2].image_base
        || address.symbol_address != leaf_symbol
        || !text_equal(&address.symbol_name, "leaf_data")) {
        return fail(45);
    }

    void *forged = (void *)(usize)0x1234;
    information.image_base = (void *)1;
    if (runtime->information(forged, &information, &error) != -1
        || information.image_base != (void *)0
        || !text_equal(&error, "loader information handle is invalid")
        || runtime->close(forged, &error) != -1
        || !text_equal(&error, "loader close handle is invalid")) {
        return fail(46);
    }

    if (runtime->close(mid_handle_one, &error) != 0
        || runtime->symbol(mid_handle_two, (const unsigned char *)"mid_value",
                           &mid_symbol, &error) != 0
        || runtime->close(mid_handle_two, &error) != 0) {
        return fail(47);
    }
    mid_symbol = (void *)1;
    if (runtime->symbol(mid_handle_one, (const unsigned char *)"mid_value",
                        &mid_symbol, &error) != -1
        || mid_symbol != (void *)0
        || !text_equal(&error, "loader symbol handle is invalid")
        || runtime->close(mid_handle_one, &error) != -1
        || !text_equal(&error, "loader close handle is invalid")) {
        return fail(48);
    }
    if (runtime->close(leaf_handle, &error) != 0
        || runtime->information(leaf_handle, &information, &error) != -1
        || !text_equal(&error, "loader information handle is invalid")) {
        return fail(49);
    }
    if (runtime->close(main_handle, &error) != 0
        || runtime->symbol(main_handle, (const unsigned char *)"mid_value",
                           &main_symbol, &error) != 0) {
        return fail(50);
    }
    generation = 99;
    if (runtime->snapshot(images, FIXED_GRAPH_IMAGE_COUNT, &count, &generation, &error) != 0
        || count != FIXED_GRAPH_IMAGE_COUNT || generation != 0) {
        return fail(51);
    }
    return 0;
}
