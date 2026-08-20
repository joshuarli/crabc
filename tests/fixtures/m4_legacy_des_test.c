#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static void make_bits(const unsigned char bytes[8], char bits[64], unsigned char noise)
{
    int i;
    for (i = 0; i < 64; i++)
        bits[i] = (char)(noise | ((bytes[i / 8] >> (7 - i % 8)) & 1));
}

static int matches(const char bits[64], const unsigned char bytes[8])
{
    int i;
    for (i = 0; i < 64; i++)
        if ((unsigned char)bits[i] != ((bytes[i / 8] >> (7 - i % 8)) & 1))
            return 0;
    return 1;
}

int main(void)
{
    /* FIPS 46-3 known-answer test: 133457799BBCDFF1 encrypts
     * 0123456789ABCDEF to 85E813540F0AB405. */
    static const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    static const unsigned char plain[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    static const unsigned char cipher[8] = {
        0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05
    };
    char key_bits[64];
    char block_bits[64];

    /* The historical interface masks every element with 1. */
    make_bits(key, key_bits, 0x40);
    make_bits(plain, block_bits, 0x20);
    setkey(key_bits);
    encrypt(block_bits, 0);
    if (!matches(block_bits, cipher)) return 1;

    /* Any nonzero edflag selects the reversed round-key schedule. */
    encrypt(block_bits, 7);
    if (!matches(block_bits, plain)) return 2;

    /* A later setkey replaces the process-global key. */
    make_bits((const unsigned char[8]){0, 0, 0, 0, 0, 0, 0, 0}, key_bits, 0);
    make_bits((const unsigned char[8]){0, 0, 0, 0, 0, 0, 0, 0}, block_bits, 0);
    setkey(key_bits);
    encrypt(block_bits, 0);
    if (!matches(block_bits,
                (const unsigned char[8]){0x8c, 0xa6, 0x4d, 0xe9, 0xc1, 0xb1, 0x23, 0xa7}))
        return 3;

    puts("m4 legacy des ok");
    return 0;
}
