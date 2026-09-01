/* One source builds a finite DT_NEEDED chain for the object-capacity negative. */
#ifndef CRABC_CURRENT_SYMBOL
#error CRABC_CURRENT_SYMBOL is required
#endif

#if defined(CRABC_NEXT_SYMBOL)
extern int CRABC_NEXT_SYMBOL(void);

int CRABC_CURRENT_SYMBOL(void) {
    return CRABC_NEXT_SYMBOL();
}
#else
int CRABC_CURRENT_SYMBOL(void) {
    return 1;
}
#endif
