/* 128 deliberately exported symbols make dlsym lookup work measurable. */
#define SYMBOL(N) int bench_symbol_##N(void) { return 0; }
#define SYMBOLS_16(BASE) \
    SYMBOL(BASE##0) SYMBOL(BASE##1) SYMBOL(BASE##2) SYMBOL(BASE##3) \
    SYMBOL(BASE##4) SYMBOL(BASE##5) SYMBOL(BASE##6) SYMBOL(BASE##7) \
    SYMBOL(BASE##8) SYMBOL(BASE##9) SYMBOL(BASE##a) SYMBOL(BASE##b) \
    SYMBOL(BASE##c) SYMBOL(BASE##d) SYMBOL(BASE##e) SYMBOL(BASE##f)

/* The runner resolves bench_symbol_7f, late in the dynsym table. */
SYMBOLS_16(0)
SYMBOLS_16(1)
SYMBOLS_16(2)
SYMBOLS_16(3)
SYMBOLS_16(4)
SYMBOLS_16(5)
SYMBOLS_16(6)
SYMBOLS_16(7)
