/*
 * One finite public object followed by private mapped padding.
 *
 * The two arrays deliberately share a one-byte-aligned input section so the
 * returned one-past address remains inside the DSO's PT_LOAD mapping but is
 * outside the four-byte dynamic symbol.  The padding stays local and is not
 * present in .dynsym; this lets the native fixture distinguish musl's object
 * identity from its finite-symbol result without adding another loader edge.
 */

enum {
    DLADDR_BOUNDED_DATA_SIZE = 4,
    DLADDR_BOUNDED_PADDING_SIZE = 64,
};

__attribute__((used, visibility("default"), section(".rodata.crabc_dladdr_bounds"), aligned(1)))
const unsigned char dladdr_bounded_data[DLADDR_BOUNDED_DATA_SIZE] = { 1, 2, 3, 4 };

__attribute__((used, section(".rodata.crabc_dladdr_bounds"), aligned(1)))
static const unsigned char dladdr_bounded_padding[DLADDR_BOUNDED_PADDING_SIZE] = { 0 };

/* Keep the required leaf-only packed RELR stream without exposing another ABI. */
__attribute__((used))
static const unsigned char *volatile dladdr_bounded_relative = dladdr_bounded_padding;

const unsigned char *dladdr_leaf_data_address(void) {
    return dladdr_bounded_data;
}

const unsigned char *dladdr_leaf_interior_address(void) {
    return dladdr_bounded_data + 1;
}

const unsigned char *dladdr_leaf_gap_address(void) {
    return dladdr_bounded_data + sizeof(dladdr_bounded_data);
}
