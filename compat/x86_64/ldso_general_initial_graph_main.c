extern int left_value(void);
extern int right_value(void);

#if defined(CRABC_GENERAL_MAIN_INIT_ARRAY)
/* Main-image constructors remain CRT-owned. The private general graph must
   reject this metadata while parsing the kernel-mapped executable. */
__attribute__((constructor)) static void main_initializer(void) {
    __builtin_trap();
}
#endif

#if defined(CRABC_GENERAL_MAIN_PREINIT_ARRAY)
static void main_preinitializer(void) {
    __builtin_trap();
}

/* Preinit remains a main/CRT lifecycle concern, never a dependency-loader
   callback. Keep this exact metadata in the negative executable fixture. */
__attribute__((used, section(".preinit_array")))
static void (*const main_preinit_array_entry)(void) = main_preinitializer;
#endif

int main(void) {
    /* Both branches require the same leaf: success proves one mapped identity
       can satisfy repeated DT_NEEDED edges without a fixed traversal shape. */
    return left_value() + right_value() == 42 ? 0 : 41;
}
