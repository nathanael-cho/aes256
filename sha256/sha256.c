#include <string.h>

#include "sha256.h"

////////////
// MACROS //
////////////

#define RL(x, y) ((x << y) | (x >> (32 - y)))
#define RR(x, y) ((x >> y) | (x << (32 - y)))
#define C(x, y, z) ((x & y) ^ ((~x) & z))
#define M(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define E0(x) (RR(x, 2) ^ RR(x, 13) ^ RR(x, 22))
#define E1(x) (RR(x, 6) ^ RR(x, 11) ^ RR(x, 25))
#define S0(x) (RR(x, 7) ^ RR(x, 18) ^ (x >> 3))
#define S1(x) (RR(x, 17) ^ RR(x, 19) ^ (x >> 10))

/////////////////////
// ROUND CONSTANTS //
/////////////////////

static const uint32_t round_constants[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/////////////
// HELPERS //
/////////////

static void sha256_transform(sha256_context* context, uint8_t* data) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, schedule[64];
    for (i = 0, j = 0; i < 16; i++, j += 4) {
        schedule[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    }
    for (; i < 64; i++) {
        schedule[i] = S1(schedule[i - 2]) + schedule[i - 7] + S0(schedule[i - 15]) + schedule[i - 16];
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + E1(e) + C(e, f, g) + round_constants[i] + schedule[i];
        t2 = E0(a) + M(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

/**
 * sha256_initialize(context)
 *
 * Initialize the SHA 256 context.
 */
void sha256_initialize(sha256_context* context) {
    context->data_length = 0;
    context->bit_length = 0;
    context->state[0] = 0x6a09e667;
    context->state[1] = 0xbb67ae85;
    context->state[2] = 0x3c6ef372;
    context->state[3] = 0xa54ff53a;
    context->state[4] = 0x510e527f;
    context->state[5] = 0x9b05688c;
    context->state[6] = 0x1f83d9ab;
    context->state[7] = 0x5be0cd19;
}

/**
 * sha256_update(context, data, length)
 *
 * Update the context.
 */
void sha256_update(sha256_context* context, uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        context->data[context->data_length++] = data[i];
        if (context->data_length == 64) {
            sha256_transform(context, context->data);
            context->bit_length += 512;
            context->data_length = 0;
        }
    }
}

/**
 * sha256_finish(context, hash)
 *
 * Finish up the SHA algorithm and return the final hash.
 */
void sha256_finish(sha256_context* context, uint8_t* hash) {
    uint32_t i = context->data_length;

    if (context->data_length < 56) {
        context->data[i++] = 0x80;
        while (i < 56) {
            context->data[i++] = 0x00;
        }
    } else {
        context->data[i++] = 0x80;
        while (i < 64) {
            context->data[i++] = 0x00;
        }
        sha256_transform(context, context->data);
        memset(context->data, 0, 56);
    }

    context->bit_length += context->data_length * 8;
    context->data[63] = context->bit_length;
    context->data[62] = context->bit_length >> 8;
    context->data[61] = context->bit_length >> 16;
    context->data[60] = context->bit_length >> 24;
    context->data[59] = context->bit_length >> 32;
    context->data[58] = context->bit_length >> 40;
    context->data[57] = context->bit_length >> 48;
    context->data[56] = context->bit_length >> 56;
    sha256_transform(context, context->data);

    for (i = 0; i < 4; i++) {
        hash[i] = (context->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (context->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (context->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (context->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (context->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (context->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (context->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (context->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

/**
 * sha256_clean_context(context)
 *
 * Zero out the context.
 */
void sha256_clean_context(sha256_context* context) {
    memset(context->data, 0, 64 * sizeof(uint8_t));
    memset(context->state, 0, 8 * sizeof(uint32_t));
    context->data_length = 0;
    context->bit_length = 0;
}

/**
 * get_sha256_hash(key, key_length, hash)
 *
 * Carry out the entire hash process.
 */
void get_sha256_hash(uint8_t* key, uint8_t key_length, uint8_t* hash) {
    sha256_context context;
    sha256_initialize(&context);
    sha256_update(&context, key, key_length);
    sha256_finish(&context, hash);
    sha256_clean_context(&context);
}
