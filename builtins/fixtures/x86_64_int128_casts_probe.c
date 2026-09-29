/* Volatile operands force the native compiler's actual 128-bit cast calls. */
typedef unsigned __int128 u128;
typedef __int128 i128;
static volatile u128 unsigned_input;
static volatile i128 signed_input;
static volatile double floating_input;

__attribute__((noinline)) static double unsigned_to_double(void) { return (double)unsigned_input; }
__attribute__((noinline)) static double signed_to_double(void) { return (double)signed_input; }
__attribute__((noinline)) static u128 double_to_unsigned(void) { return (u128)floating_input; }
__attribute__((noinline)) static i128 double_to_signed(void) { return (i128)floating_input; }

int crabc_x86_64_int128_casts_probe(void) {
    const u128 one=1;
    for (unsigned bit=0;bit<128;++bit) {
        u128 value=one<<bit;
        unsigned_input=value;
        double expected=1.0;
        for (unsigned i=0;i<bit;++i) expected*=2.0;
        if (unsigned_to_double()!=expected) return 1;
        floating_input=expected;
        if (double_to_unsigned()!=value) return 2;
        if (bit<127) {
            signed_input=(i128)value;
            if (signed_to_double()!=expected) return 3;
            floating_input=-expected;
            if (double_to_signed()!=-(i128)value) return 4;
            signed_input=-(i128)value;
            if (signed_to_double()!=-expected) return 5;
        }
    }
    unsigned_input=(one<<100)+(one<<47);
    if (unsigned_to_double()!=0x1p100) return 6;
    unsigned_input=(one<<100)+(one<<47)+1;
    if (unsigned_to_double()!=0x1.0000000000001p100) return 7;
    unsigned_input=(one<<100)+(one<<48)+(one<<47);
    if (unsigned_to_double()!=0x1.0000000000002p100) return 8;
    signed_input=-((i128)one<<100)-((i128)one<<47)-1;
    if (signed_to_double()!=-0x1.0000000000001p100) return 9;
    floating_input=0x1.fffffffffffffp126;
    if (double_to_signed()!=(i128)((one<<127)-(one<<74))) return 10;
    floating_input=0x1.fffffffffffffp127;
    if (double_to_unsigned()!=~(u128)0-(one<<75)+1) return 11;
    floating_input=-0x1p127;
    if ((u128)double_to_signed()!=(one<<127)) return 12;
    floating_input=-17.75;
    if (double_to_signed()!=-17) return 13;
    floating_input=17.75;
    if (double_to_unsigned()!=17) return 14;
    floating_input=0x1p-1022;
    if (double_to_unsigned()!=0 || double_to_signed()!=0) return 15;
    floating_input=-0.0;
    if (double_to_unsigned()!=0 || double_to_signed()!=0) return 16;
    return 0;
}
