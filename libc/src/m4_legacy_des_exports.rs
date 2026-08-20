// Legacy DES bit-array APIs from musl's src/crypt/encrypt.c.
//
// setkey() and encrypt() are intentionally process-global and non-reentrant,
// matching the historical ABI.  Their arguments are not byte-oriented DES
// inputs: each of the 64 array elements contains one bit in its low bit, and
// the first element is the most-significant bit of the key or block.

const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

const KEY_SHIFTS: [u8; 16] = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
];

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
];

const EXPANSION: [u8; 48] = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
];

const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25,
];

const SBOXES: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

struct LegacyDesKey {
    round_keys: [u64; 16],
}

static mut LEGACY_DES_KEY: LegacyDesKey = LegacyDesKey { round_keys: [0; 16] };

#[inline]
fn permute(input: u64, table: &[u8], input_bits: u32) -> u64 {
    let mut output = 0u64;
    let mut i = 0;
    while i < table.len() {
        output = (output << 1) | ((input >> (input_bits - table[i] as u32)) & 1);
        i += 1;
    }
    output
}

fn expand_key(key: u64) -> LegacyDesKey {
    let pc1 = permute(key, &PC1, 64);
    let mut left = (pc1 >> 28) & 0x0fff_ffff;
    let mut right = pc1 & 0x0fff_ffff;
    let mut round_keys = [0u64; 16];

    let mut i = 0;
    while i < 16 {
        let shift = KEY_SHIFTS[i] as u32;
        left = ((left << shift) | (left >> (28 - shift))) & 0x0fff_ffff;
        right = ((right << shift) | (right >> (28 - shift))) & 0x0fff_ffff;
        round_keys[i] = permute((left << 28) | right, &PC2, 56);
        i += 1;
    }
    LegacyDesKey { round_keys }
}

#[inline]
fn feistel(right: u32, round_key: u64) -> u32 {
    let expanded = permute(right as u64, &EXPANSION, 32) ^ round_key;
    let mut substituted = 0u32;
    let mut i = 0;
    while i < 8 {
        let six = ((expanded >> (42 - i * 6)) & 0x3f) as usize;
        let row = ((six & 0x20) >> 4) | (six & 1);
        let column = (six >> 1) & 0x0f;
        substituted = (substituted << 4) | SBOXES[i][row * 16 + column] as u32;
        i += 1;
    }
    permute(substituted as u64, &P, 32) as u32
}

fn des_block(block: u64, round_keys: &[u64; 16]) -> u64 {
    let initial = permute(block, &IP, 64);
    let mut left = (initial >> 32) as u32;
    let mut right = initial as u32;
    let mut i = 0;
    while i < 16 {
        let next_left = right;
        let next_right = left ^ feistel(right, round_keys[i]);
        left = next_left;
        right = next_right;
        i += 1;
    }
    permute(((right as u64) << 32) | left as u64, &FP, 64)
}

#[no_mangle]
pub unsafe extern "C" fn setkey(key: *const c_char) {
    let mut key_bits = 0u64;
    let mut i = 0;
    while i < 64 {
        key_bits = (key_bits << 1) | ((*key.add(i) as u8 & 1) as u64);
        i += 1;
    }
    LEGACY_DES_KEY = expand_key(key_bits);
}

#[no_mangle]
pub unsafe extern "C" fn encrypt(block: *mut c_char, edflag: c_int) {
    let mut block_bits = 0u64;
    let mut i = 0;
    while i < 64 {
        block_bits = (block_bits << 1) | ((*block.add(i) as u8 & 1) as u64);
        i += 1;
    }

    let mut round_keys = [0u64; 16];
    i = 0;
    while i < 16 {
        round_keys[i] = if edflag != 0 {
            LEGACY_DES_KEY.round_keys[15 - i]
        } else {
            LEGACY_DES_KEY.round_keys[i]
        };
        i += 1;
    }

    let encrypted = des_block(block_bits, &round_keys);
    i = 0;
    while i < 64 {
        *block.add(i) = ((encrypted >> (63 - i)) & 1) as c_char;
        i += 1;
    }
}
