#include "aes256.h"

//////////////////////
// SUBSTITUTION BOX //
//////////////////////

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t sbox_inverse[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

inline static uint8_t get_sbox(unsigned char x) {
    return sbox[x];
}

inline static uint8_t get_sbox_inverse(unsigned char x) {
    return sbox_inverse[x];
}

/////////////////////
// AES 256 HELPERS //
/////////////////////

inline static uint8_t next_round_constant(uint8_t x) {
    uint8_t y = (uint8_t) (x << 1);
    return (x & 0x80) ? (y ^ 0x1b) : y;
}

inline static uint8_t previous_round_constant(uint8_t x) {
    return (x >> 1) ^ ((x & 1) ? 0x8d : 0);
}

// https://en.wikipedia.org/wiki/Rijndael_key_schedule
static void aes256_expand_key(uint8_t* key, uint8_t* round_constant) {
    key[0] ^= get_sbox(key[29]) ^ (*round_constant);
    key[1] ^= get_sbox(key[30]);
    key[2] ^= get_sbox(key[31]);
    key[3] ^= get_sbox(key[28]);
    *round_constant = next_round_constant(*round_constant);
    for (uint8_t i = 4; i < 16; i += 4) {
        key[i] ^= key[i - 4];
        key[i + 1] ^= key[i - 3];
        key[i + 2] ^= key[i - 2];
        key[i + 3] ^= key[i - 1];
    }

    key[16] ^= get_sbox(key[12]);
    key[17] ^= get_sbox(key[13]);
    key[18] ^= get_sbox(key[14]);
    key[19] ^= get_sbox(key[15]);
    for (uint8_t i = 20; i < 32; i += 4) {
        key[i] ^= key[i - 4];
        key[i + 1] ^= key[i - 3];
        key[i + 2] ^= key[i - 2];
        key[i + 3] ^= key[i - 1];
    }
}

static void aes256_reverse_key_expansion(uint8_t* key, uint8_t* round_constant) {
    for (uint8_t i = 28; i > 16; i -= 4) {
        key[i] ^= key[i - 4];
        key[i + 1] ^= key[i - 3];
        key[i + 2] ^= key[i - 2];
        key[i + 3] ^= key[i - 1];
    }
    key[16] ^= get_sbox(key[12]);
    key[17] ^= get_sbox(key[13]);
    key[18] ^= get_sbox(key[14]);
    key[19] ^= get_sbox(key[15]);

    for (uint8_t i = 12; i > 0; i -= 4) {
        key[i] ^= key[i - 4];
        key[i + 1] ^= key[i - 3];
        key[i + 2] ^= key[i - 2];
        key[i + 3] ^= key[i - 1];
    }
    *round_constant = previous_round_constant(*round_constant);
    key[0] ^= get_sbox(key[29]) ^ (*round_constant);
    key[1] ^= get_sbox(key[30]);
    key[2] ^= get_sbox(key[31]);
    key[3] ^= get_sbox(key[28]);
}

static void aes256_add_round_key(uint8_t* buffer, uint8_t* key) {
    for (uint8_t i = 0; i < 16; i++) {
        buffer[i] ^= key[i];
    }
}

static void aes256_add_round_key_with_copy(uint8_t* buffer, uint8_t* key, uint8_t* copy) {
    for (uint8_t i = 0; i < 16; i++) {
        buffer[i] ^= (copy[i] = key[i]);
        copy[i + 16] = key[i + 16];
    }
}

static void aes256_substitute_bytes(uint8_t* buffer) {
    for (uint8_t i = 0; i < 16; i++) {
        buffer[i] = get_sbox(buffer[i]);
    }
}

static void aes256_reverse_byte_substitution(uint8_t* buffer) {
    for (uint8_t i = 0; i < 16; i++) {
        buffer[i] = get_sbox_inverse(buffer[i]);
    }
}

static void aes256_shift_rows(uint8_t* buffer) {
    uint8_t i = buffer[1];
    buffer[1] = buffer[5];
    buffer[5] = buffer[9];
    buffer[9] = buffer[13];
    buffer[13] = i;

    i = buffer[10];
    buffer[10] = buffer[2];
    buffer[2] = i;

    i = buffer[14];
    buffer[14] = buffer[6];
    buffer[6] = i;

    i = buffer[3];
    buffer[3] = buffer[15];
    buffer[15] = buffer[11];
    buffer[11] = buffer[7];
    buffer[7] = i;
}

static void aes256_reverse_row_shift(uint8_t* buffer) {
    uint8_t i = buffer[1];
    buffer[1] = buffer[13];
    buffer[13] = buffer[9];
    buffer[9] = buffer[5];
    buffer[5] = i;

    i = buffer[10];
    buffer[10] = buffer[2];
    buffer[2] = i;

    i = buffer[14];
    buffer[14] = buffer[6];
    buffer[6] = i;

    i = buffer[3];
    buffer[3] = buffer[7];
    buffer[7] = buffer[11];
    buffer[11] = buffer[15];
    buffer[15] = i;
}

static void aes256_mix_columns(uint8_t* buffer) {
    for (uint8_t i = 0; i < 16; i  += 4) {
        uint8_t a = buffer[i];
        uint8_t b = buffer[i + 1];
        uint8_t c = buffer[i + 2];
        uint8_t d = buffer[i + 3];
        uint8_t e = a ^ b ^ c ^ d;
        buffer[i] ^= e ^ next_round_constant(a ^ b);
        buffer[i + 1] ^= e ^ next_round_constant(b ^ c);
        buffer[i + 2] ^= e ^ next_round_constant(c ^ d);
        buffer[i + 3] ^= e ^ next_round_constant(d ^ a);
    }
}

static void aes256_reverse_column_mix(uint8_t* buffer) {
    for (uint8_t i = 0; i < 16; i += 4) {
        uint8_t a = buffer[i];
        uint8_t b = buffer[i + 1];
        uint8_t c = buffer[i + 2];
        uint8_t d = buffer[i + 3];
        uint8_t e = a ^ b ^ c ^ d;
        uint8_t z = next_round_constant(e);
        uint8_t x = e ^ next_round_constant(next_round_constant(z ^ a ^ c));
        uint8_t y = e ^ next_round_constant(next_round_constant(z ^ b ^ d));
        buffer[i] ^= x ^ next_round_constant(a ^ b);
        buffer[i + 1] ^= y ^ next_round_constant(b ^ c);
        buffer[i + 2] ^= x ^ next_round_constant(c ^ d);
        buffer[i + 3] ^= y ^ next_round_constant(d ^ a);
    }
}

/////////////
// AES 256 //
/////////////

/**
 * aes256_initialize(keys, seed_key)
 *
 * Initialize the algorithm keys.
 */
void aes256_initialize(aes256_keys* keys, uint8_t* seed_key) {
    uint8_t round_constant = 1;
    copy_array(keys->encryption_key, seed_key, sizeof(keys->encryption_key));
    copy_array(keys->decryption_key, seed_key, sizeof(keys->encryption_key));
    // https://en.wikipedia.org/wiki/Rijndael_key_schedule
    for (uint8_t i = 0; i < 7; i++) {
        aes256_expand_key(keys->decryption_key, &round_constant);
    }
}

/**
 * aes256_cleanup(keys)
 *
 * Zero out the keys.
 */
void aes256_cleanup(aes256_keys* keys) {
    zero_array(keys->round_key, sizeof(keys->round_key));
    zero_array(keys->round_key, sizeof(keys->encryption_key));
    zero_array(keys->round_key, sizeof(keys->decryption_key));
}

/**
 * aes256_encrypt(keys, buffer)
 *
 * Encrypt the buffer using the given keys.
 */
void aes256_encrypt(aes256_keys* keys, uint8_t* buffer) {
    uint8_t round_constant = 1;

    aes256_add_round_key_with_copy(buffer, keys->encryption_key, keys->round_key);
    for (uint8_t i = 1; i < 14; i++) {
        aes256_substitute_bytes(buffer);
        aes256_shift_rows(buffer);
        aes256_mix_columns(buffer);
        if (i & 1) {
            aes256_add_round_key(buffer, keys->round_key + 16);
        } else {
            aes256_expand_key(keys->round_key, &round_constant);
            aes256_add_round_key(buffer, keys->round_key);
        }
    }
    aes256_substitute_bytes(buffer);
    aes256_shift_rows(buffer);
    aes256_expand_key(keys->round_key, &round_constant);
    aes256_add_round_key(buffer, keys->round_key);
}

/**
 * aes256_decrypt(keys, buffer)
 *
 * Decrypt the buffer using the given keys.
 */
void aes256_decrypt(aes256_keys* keys, uint8_t* buffer) {
    uint8_t round_constant = 0x80;

    aes256_add_round_key_with_copy(buffer, keys->decryption_key, keys->round_key);
    aes256_reverse_row_shift(buffer);
    aes256_reverse_byte_substitution(buffer);

    for (uint8_t i = 13; i > 0; i--) {
        if (i & 1) {
            aes256_reverse_key_expansion(keys->round_key, &round_constant);
            aes256_add_round_key(buffer, keys->round_key + 16);
        } else {
            aes256_add_round_key(buffer, keys->round_key);
        }

        aes256_reverse_column_mix(buffer);
        aes256_reverse_row_shift(buffer);
        aes256_reverse_byte_substitution(buffer);
    }

    aes256_add_round_key(buffer, keys->round_key);
}
