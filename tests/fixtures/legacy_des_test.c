#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void make_bits(const unsigned char bytes[8], char bits[64], unsigned char noise)
{
    int i;
    for (i = 0; i < 64; i++)
        bits[i] = (char)(noise | ((bytes[i / 8] >> (7 - i % 8)) & 1));
}

int main(void)
{
    /* The legacy DES ABI is retained as an inert compatibility boundary.
     * crabc deliberately does not implement a local cipher. */
    static const unsigned char key[8] = {
        0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1
    };
    static const unsigned char plain[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    char key_bits[64];
    char block_bits[64];
    char before[64];

    /* The historical interface masks every element with 1. */
    make_bits(key, key_bits, 0x40);
    make_bits(plain, block_bits, 0x20);
    memcpy(before, block_bits, sizeof before);
    setkey(key_bits);
    encrypt(block_bits, 0);
    if (memcmp(block_bits, before, sizeof before) != 0) return 1;

    /* Any nonzero edflag selects the reversed round-key schedule. */
    encrypt(block_bits, 7);
    if (memcmp(block_bits, before, sizeof before) != 0) return 2;

    /* A later setkey replaces the process-global key. */
    make_bits((const unsigned char[8]){0, 0, 0, 0, 0, 0, 0, 0}, key_bits, 0);
    make_bits((const unsigned char[8]){0, 0, 0, 0, 0, 0, 0, 0}, block_bits, 0);
    memcpy(before, block_bits, sizeof before);
    setkey(key_bits);
    encrypt(block_bits, 0);
    if (memcmp(block_bits, before, sizeof before) != 0)
        return 3;

    puts("c-abi legacy des unsupported");
    return 0;
}
