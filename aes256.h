#ifndef __AES256__
#define __AES256__

/**
 * The code is largely taken from the following implementation:
 *     http://www.literatecode.com/get/aes256.c
 *
 * The explanation for everything can be found on Wikipedia:
 *     https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "sha256/sha256.h"

#define PASSWORD_LIMIT 128

#define IGNORE(x) if(x) {}

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

int aes256_encrypt_file(char* name);
int aes256_decrypt_file(char* name);

#endif
