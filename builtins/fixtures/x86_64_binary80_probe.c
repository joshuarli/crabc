/* Every operand is representable in its destination C type. Volatile inputs
 * retain the compiler's ordinary binary80 conversion and complex calls. */
typedef __int128 i128;
typedef unsigned __int128 u128;
typedef long double _Complex complex80;
volatile i128 signed_value = -((i128)1 << 100);
volatile u128 unsigned_value = (u128)1 << 100;
volatile long double signed_float = -0x1p100L;
volatile long double unsigned_float = 0x1p100L;
volatile complex80 complex_left = 4.0L + 2.0Li;
volatile complex80 complex_right = 2.0L + 0.0Li;
__attribute__((noinline)) complex80 multiply80(complex80 a, complex80 b) { return a*b; }
__attribute__((noinline)) complex80 divide80(complex80 a, complex80 b) { return a/b; }
int main(void) {
    if ((long double)signed_value != -0x1p100L) return 1;
    if ((long double)unsigned_value != 0x1p100L) return 2;
    if ((i128)signed_float != -((i128)1 << 100)) return 3;
    if ((u128)unsigned_float != ((u128)1 << 100)) return 4;
    complex80 p=multiply80(complex_left,complex_right);
    complex80 q=divide80(complex_left,complex_right);
    if (__real__ p!=8.0L || __imag__ p!=4.0L) return 5;
    if (__real__ q!=2.0L || __imag__ q!=1.0L) return 6;
    return 0;
}
