#ifndef __AES256__
#define __AES256__

#include <stdio.h>

#define uint8_t unsigned char

typedef struct aes256_keys {
    uint8_t round_key[32];
    uint8_t encryption_key[32];
    uint8_t decryption_key[32];
} aes256_keys;

void aes256_initialize(aes256_keys* keys, uint8_t* seed_key);
void aes256_cleanup(aes256_keys* keys);
void aes256_encrypt(aes256_keys* keys, uint8_t* buffer);
void aes256_decrypt(aes256_keys* keys, uint8_t* buffer);

#endif
