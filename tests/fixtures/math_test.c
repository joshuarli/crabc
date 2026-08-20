#include <math.h>
#include <stdio.h>

static int check(double got, double want, double eps) {
    return (got > want - eps && got < want + eps) ? 0 : 1;
}

static int checkf(float got, float want, float eps) {
    return (got > want - eps && got < want + eps) ? 0 : 1;
}

static int same_bits(double got, double want) {
    union { double f; unsigned long long i; } a = { got }, b = { want };
    return a.i == b.i;
}

static int same_bitsf(float got, float want) {
    union { float f; unsigned int i; } a = { got }, b = { want };
    return a.i == b.i;
}

int main(void) {
    int e;
    double iptr;
    float iptrf;

    if (check(sqrt(4.0), 2.0, 1e-9)) return 1;
    if (check(fabs(-3.5), 3.5, 1e-9)) return 2;
    if (check(floor(2.7), 2.0, 1e-9)) return 3;
    if (check(ceil(2.1), 3.0, 1e-9)) return 4;
    if (check(sin(0.0), 0.0, 1e-9)) return 5;
    if (check(cos(0.0), 1.0, 1e-9)) return 6;
    if (check(pow(2.0, 3.0), 8.0, 1e-9)) return 7;
    if (check(log(exp(1.0)), 1.0, 1e-9)) return 8;
    if (checkf(sqrtf(4.0f), 2.0f, 1e-6f)) return 9;

    if (check(trunc(2.9), 2.0, 1e-9)) return 10;
    if (check(trunc(-2.9), -2.0, 1e-9)) return 11;
    if (check(round(2.4), 2.0, 1e-9)) return 12;
    if (check(round(2.6), 3.0, 1e-9)) return 13;
    if (check(round(-2.5), -3.0, 1e-9)) return 14;
    if (check(copysign(1.0, -2.0), -1.0, 1e-9)) return 15;
    if (check(copysign(-1.0, 2.0), 1.0, 1e-9)) return 16;
    if (check(scalbn(1.5, 2), 6.0, 1e-9)) return 17;
    if (check(ldexp(1.5, 2), 6.0, 1e-9)) return 18;

    if (check(frexp(6.0, &e), 0.75, 1e-9)) return 19;
    if (e != 3) return 20;
    if (check(modf(3.75, &iptr), 0.75, 1e-9)) return 21;
    if (check(iptr, 3.0, 1e-9)) return 22;
    if (check(modf(-3.75, &iptr), -0.75, 1e-9)) return 23;
    if (check(iptr, -3.0, 1e-9)) return 24;

    if (checkf(truncf(2.9f), 2.0f, 1e-6f)) return 25;
    if (checkf(truncf(-2.9f), -2.0f, 1e-6f)) return 26;
    if (checkf(roundf(2.4f), 2.0f, 1e-6f)) return 27;
    if (checkf(roundf(2.6f), 3.0f, 1e-6f)) return 28;
    if (checkf(roundf(-2.5f), -3.0f, 1e-6f)) return 29;
    if (checkf(copysignf(1.0f, -2.0f), -1.0f, 1e-6f)) return 30;
    if (checkf(scalbnf(1.5f, 2), 6.0f, 1e-6f)) return 31;
    if (checkf(ldexpf(1.5f, 2), 6.0f, 1e-6f)) return 32;

    if (checkf(frexpf(6.0f, &e), 0.75f, 1e-6f)) return 33;
    if (e != 3) return 34;
    if (checkf(modff(3.75f, &iptrf), 0.75f, 1e-6f)) return 35;
    if (checkf(iptrf, 3.0f, 1e-6f)) return 36;
    if (checkf(modff(-3.75f, &iptrf), -0.75f, 1e-6f)) return 37;
    if (checkf(iptrf, -3.0f, 1e-6f)) return 38;

    if (check(sqrt(2.0), 1.4142135623730951, 1e-12)) return 39;
    if (checkf(sqrtf(2.0f), 1.4142135f, 1e-5f)) return 40;
    if (check(fmod(5.5, 2.0), 1.5, 1e-12)) return 41;
    if (checkf(fmodf(5.5f, 2.0f), 1.5f, 1e-6f)) return 42;
    if (check(sin(0.5235987755982989), 0.5, 1e-12)) return 43;
    if (check(cos(0.5235987755982989), 0.8660254037844386, 1e-12)) return 44;
    if (check(tan(0.7853981633974483), 1.0, 1e-12)) return 45;
    if (check(sin(-0x1.5f9f1bdb17192p+749), 0.623779899189803, 1e-12)) return 46;
    if (checkf(sinf(-0x1.a206fp+2f), -0.24593880772590637f, 1e-5f)) return 47;
    if (checkf(cosf(-0x1.a206fp+2f), 0.9692853689193726f, 1e-5f)) return 48;
    if (checkf(tanf(-0x1.a206fp+2f), -0.2537320852279663f, 1e-5f)) return 49;

    /* Wave 3: exp/log/pow exact identities and edge cases */
    if (check(exp(0.0), 1.0, 1e-12)) return 50;
    if (check(exp(1.0), 2.718281828459045, 1e-12)) return 51;
    if (check(log(1.0), 0.0, 1e-12)) return 52;
    if (check(log2(1.0), 0.0, 1e-12)) return 53;
    if (check(log10(1.0), 0.0, 1e-12)) return 54;
    if (check(pow(2.0, 10.0), 1024.0, 1e-9)) return 55;
    if (check(pow(0.0, 3.0), 0.0, 1e-9)) return 56;
    if (check(pow(-2.0, 3.0), -8.0, 1e-9)) return 57;
    if (check(pow(2.0, -1074.0), 0x1p-1074, 1e-20)) return 58;
    if (check(pow(2.0, -1075.0), 0.0, 1e-20)) return 59;
    if (check(pow(0x1p-1072, 1.0), 0x1p-1072, 1e-20)) return 60;
    if (check(pow(0x1p-537, 2.0), 0x1p-1074, 1e-20)) return 61;
    if (check(pow(0x1p+1023, -1.0), 0x1p-1023, 1e-20)) return 62;
    if (checkf(expf(0.0f), 1.0f, 1e-6f)) return 63;
    if (checkf(logf(1.0f), 0.0f, 1e-6f)) return 64;
    if (checkf(log2f(1.0f), 0.0f, 1e-6f)) return 65;
    if (checkf(powf(2.0f, 10.0f), 1024.0f, 1e-3f)) return 66;
    if (checkf(powf(-2.0f, 3.0f), -8.0f, 1e-5f)) return 67;
    if (checkf(powf(0x1p-63f, 2.0f), 0x1p-126f, 1e-7f)) return 68;

    /* Wave 4: hyperbolic, inverse trig, hypot, lrint family */
    if (check(hypot(3.0, 4.0), 5.0, 1e-12)) return 69;
    if (check(hypot(1e200, 1e200), 1.4142135623730951e200, 1e185)) return 70;
    if (checkf(hypotf(3.0f, 4.0f), 5.0f, 1e-6f)) return 71;
    if (check(sinh(0.0), 0.0, 1e-12)) return 72;
    if (check(cosh(0.0), 1.0, 1e-12)) return 73;
    if (check(tanh(0.0), 0.0, 1e-12)) return 74;
    if (check(sinh(0.881373587019543), 1.0, 1e-12)) return 75;
    if (check(cosh(0.881373587019543), 1.4142135623730951, 1e-12)) return 76;
    if (check(tanh(0.5493061443340549), 0.5, 1e-12)) return 77;
    if (checkf(sinhf(0.0f), 0.0f, 1e-6f)) return 78;
    if (checkf(coshf(0.0f), 1.0f, 1e-6f)) return 79;
    if (checkf(tanhf(0.0f), 0.0f, 1e-6f)) return 80;
    if (check(asin(0.0), 0.0, 1e-12)) return 81;
    if (check(asin(1.0), 1.5707963267948966, 1e-12)) return 82;
    if (check(acos(1.0), 0.0, 1e-12)) return 83;
    if (check(acos(0.0), 1.5707963267948966, 1e-12)) return 84;
    if (check(atan(1.0), 0.7853981633974483, 1e-12)) return 85;
    if (check(atan2(1.0, 0.0), 1.5707963267948966, 1e-12)) return 86;
    if (checkf(asinf(0.0f), 0.0f, 1e-6f)) return 87;
    if (checkf(acosf(1.0f), 0.0f, 1e-6f)) return 88;
    if (checkf(atanf(1.0f), 0.7853981633974483f, 1e-6f)) return 89;
    if (checkf(atan2f(1.0f, 0.0f), 1.5707963267948966f, 1e-6f)) return 90;
    if (lrint(2.3) != 2) return 91;
    if (lrint(2.7) != 3) return 92;
    if (llrint(2.7) != 3) return 93;
    if (lrintf(2.3f) != 2) return 94;
    if (llrintf(2.7f) != 3) return 95;
    if (lrintl(2.3L) != 2) return 96;
    if (llrintl(2.7L) != 3) return 97;
    if (check(sinh(0x1.d3e0d2f5d98d6p-2), 0x1.e45428082fb8cp-2, 1e-15)) return 98;

    /* Pinned musl 1.2.6 vectors that exercise the inverse/hyperbolic edges. */
    if (!same_bits(acosh(0x1.001f1c62cf304p+0), 0x1.f8d125ff71cc2p-6)) return 99;
    if (!same_bits(asinh(0x1.fbdd0eedf8143p-3), 0x1.f6cc20d7a594cp-3)) return 100;
    if (!same_bits(sinh(0x1.d3e0d2f5d98d6p-2), 0x1.e45428082fb8ap-2)) return 101;

    /* Pinned musl Bessel vectors, including near-zero cancellation cases. */
    if (!same_bits(j0(-0x1.33d132fd04a92p+1), 0x1.092b2a541b1a0p-19)) return 102;
    if (!same_bits(j0(-0x1.33d15297be06fp+1), 0x1.5352913ddb41bp-26)) return 103;
    if (!same_bits(j0(0x1.33d152e971b4p+1), -0x1.00209921727cbp-54)) return 104;
    if (!same_bits(j0(0x1.6148f5b2c2e45p+2), -0x1.ebcb069d486ccp-56)) return 105;
    if (!same_bits(j0(0x1.14eb56cccdecap+3), -0x1.6d2a820627412p-54)) return 106;
    if (!same_bits(jn(5, 0x1.1f9ef934745cbp-1), 0x1.e274364abf2d2p-17)) return 107;
    if (!same_bits(y0(0x1.c982eb8d417eap-1), -0x1.0000000000000p-55)) return 108;
    if (!same_bits(y0(0x1.c982eb8d417ebp-1), 0x1.2p-54)) return 109;
    if (!same_bits(y0(0x1.fa9534d98569bp+1), 0x1.3004a968fceadp-53)) return 110;
    if (!same_bits(y0(0x1.fa9534d98569cp+1), -0x1.8f4eb84cc2a33p-55)) return 111;
    if (!same_bits(y0(0x1.c581dc4e72102p+2), -0x1.16eb61aad4cacp-52)) return 112;
    /* Pinned musl gamma vectors and sign contracts. */
    if (!same_bits(lgamma_r(-0x1.02239f3c6a8f1p+3, &e),
                   -0x1.0120f61b63d5ep+3)) return 121;
    if (e != -1) return 122;
    if (!same_bits(lgamma(-0x1.02239f3c6a8f1p+3),
                   -0x1.0120f61b63d5ep+3)) return 123;
    if (signgam != -1) return 124;
    if (!same_bitsf(lgammaf_r(-0x1.0223ap+3f, &e),
                    -0x1.012104p+3f)) return 125;
    if (e != -1) return 126;
    if (!same_bitsf(lgammaf(-0x1.0223ap+3f),
                    -0x1.012104p+3f)) return 127;
    if (signgam != -1) return 128;
    if (check(tgamma(-0x1.02239f3c6a8f1p+3),
              -0x1.53910aafcfc6ep-12, 0x1p-63)) return 129;
    if (check(tgamma(0x1.161868e18bc67p+2),
              0x1.2d21bb9ee4ac5p+3, 0x1p-48)) return 130;
    if (check(tgamma(0x1p-1), 0x1.c5bf891b4ef6bp+0, 0x1p-51)) return 131;

    /* The pinned musl oracle emits these exact bits for libc-test's X cases. */
    if (!same_bits(lgamma_r(-0x1.4p+1, &e), -0x1.ccbf9f5ed0f2p-5)) return 132;
    if (e != -1) return 133;
    if (!same_bits(lgamma(-0x1.4p+1), -0x1.ccbf9f5ed0f2p-5)) return 134;
    if (signgam != -1) return 135;
    if (!same_bitsf(lgammaf_r(-0x1.0c34b4p+3f, &e), -0x1.46d736p+3f)) return 136;
    if (e != -1) return 137;
    if (!same_bitsf(lgammaf(-0x1.0c34b4p+3f), -0x1.46d736p+3f)) return 138;
    if (signgam != -1) return 139;
    if (!same_bits(tgamma(-0x1.a206f0a19dcc4p+2),
                   -0x1.9fd0c1ce12f12p-10)) return 140;
    if (!same_bits(tgamma(0x1p-53), 0x1.ffffffffffffdp+52)) return 141;
    if (!same_bits(tgamma(-0x1.0000000000001p+0),
                   0x1.ffffffffffffdp+51)) return 142;

    printf("math ok\n");
    return 0;
}
