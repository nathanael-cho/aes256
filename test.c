#include <stdlib.h>
#include <stdio.h>

#include "aes256.h"

void dump(char* prefix, uint8_t* buffer) {
    printf("%s", prefix);
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

int main (void) {
    aes256_keys keys;
    uint8_t round_key[32];
    uint8_t buffer[16];

    for (uint8_t i = 0; i < sizeof(buffer); i++) {
        buffer[i] = i * 16 + i;
    }
    for (uint8_t i = 0; i < sizeof(round_key);i++) {
        round_key[i] = i;
    }

    dump("Text: ", buffer);
    dump("Key: ", round_key);
    printf("---\n");

    aes256_initialize(&keys, round_key);
    aes256_encrypt(&keys, buffer);

    dump("Encoding: ", buffer);
    printf("Expected Encoding: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89\n");

    aes256_initialize(&keys, round_key);
    aes256_decrypt(&keys, buffer);
    dump("Decrypted: ", buffer);

    aes256_cleanup(&keys);

    return 0;
}
