/* Volatile operands retain the compiler's four binary32/integer128 calls. */
typedef unsigned __int128 u128;
typedef __int128 i128;
_Static_assert(sizeof(float)==4 && __FLT_MANT_DIG__==24 && __FLT_MAX_EXP__==128,
               "requires IEEE binary32");
_Static_assert(sizeof(u128)==16 && __FLT_EVAL_METHOD__==0,
               "requires native integer128 and SSE evaluation");
static volatile u128 unsigned_input;
static volatile i128 signed_input;
static volatile float floating_input;
__attribute__((noinline)) static float from_unsigned(void) { return (float)unsigned_input; }
__attribute__((noinline)) static float from_signed(void) { return (float)signed_input; }
__attribute__((noinline)) static u128 to_unsigned(void) { return (u128)floating_input; }
__attribute__((noinline)) static i128 to_signed(void) { return (i128)floating_input; }

int crabc_x86_64_binary32_casts_probe(void) {
    const u128 one=1;
    for (unsigned bit=0;bit<128;++bit) {
        u128 value=one<<bit;
        float expected=1.0f;
        for (unsigned i=0;i<bit;++i) expected*=2.0f;
        unsigned_input=value;
        if (from_unsigned()!=expected) return 1;
        floating_input=expected;
        if (to_unsigned()!=value) return 2;
        if (bit<127) {
            signed_input=(i128)value;
            if (from_signed()!=expected) return 3;
            floating_input=-expected;
            if (to_signed()!=-(i128)value) return 4;
            signed_input=-(i128)value;
            if (from_signed()!=-expected) return 5;
        }
    }
    unsigned_input=(one<<100)+(one<<76);
    if (from_unsigned()!=0x1p100f) return 6;
    unsigned_input=(one<<100)+(one<<76)+1;
    if (from_unsigned()!=0x1.000002p100f) return 7;
    unsigned_input=(one<<100)+(one<<77)+(one<<76);
    if (from_unsigned()!=0x1.000004p100f) return 8;
    signed_input=-((i128)one<<100)-((i128)one<<76)-1;
    if (from_signed()!=-0x1.000002p100f) return 9;
    floating_input=0x1.fffffep126f;
    if (to_signed()!=(i128)((one<<127)-(one<<103))) return 10;
    floating_input=0x1.fffffep127f;
    if (to_unsigned()!=~(u128)0-(one<<104)+1) return 11;
    floating_input=-0x1p127f;
    if ((u128)to_signed()!=(one<<127)) return 12;
    floating_input=-17.75f;
    if (to_signed()!=-17) return 13;
    floating_input=17.75f;
    if (to_unsigned()!=17) return 14;
    floating_input=0x1p-126f;
    if (to_unsigned()!=0 || to_signed()!=0) return 15;
    floating_input=-0.0f;
    if (to_unsigned()!=0 || to_signed()!=0) return 16;
    return 0;
}
