#include <memory.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

int main(void) {
    uint8_t* text1 = (uint8_t*) "abc";
    uint8_t* text2 = (uint8_t*) "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    uint8_t expected1[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t expected2[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };

    uint8_t hash[32];
    sha256_context context;

    sha256_initialize(&context);
    sha256_update(&context, text1, strlen((char*) text1));
    sha256_finish(&context, hash);

    int status = !memcmp(hash, expected1, 32);
    printf("The hash for %s is %s.\n", text1, status ? "correct" : "incorrect");

    sha256_initialize(&context);
    sha256_update(&context, text2, strlen((char*) text2));
    sha256_finish(&context, hash);

    sha256_clean_context(&context);

    status = !memcmp(hash, expected2, 32);
    printf("The hash for %s is %s.\n", text2, status ? "correct" : "incorrect");

    for (uint8_t i = 0; i < 32; i++) {
        hash[i] = 0;
    }

    return 0;
}
