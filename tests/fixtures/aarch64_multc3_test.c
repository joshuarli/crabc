#include <stdio.h>

extern long double _Complex __multc3(long double, long double, long double, long double);
int main(void) {
    long double infinity = __builtin_infl();
    long double nan = __builtin_nanl("");
    long double _Complex value = __multc3(3.0L, 4.0L, 5.0L, 6.0L);
    if (__real__ value != -9.0L || __imag__ value != 38.0L) return 1;
    value = __multc3(infinity, nan, 2.0L, 3.0L);
    if (!__builtin_isinf(__real__ value) || !__builtin_isinf(__imag__ value)) return 2;
    value = __multc3(nan, nan, 2.0L, 3.0L);
    if (!__builtin_isnan(__real__ value) || !__builtin_isnan(__imag__ value)) return 3;
    puts("multc3 ok");
    return 0;
}
