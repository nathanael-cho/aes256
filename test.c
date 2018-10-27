#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "aes256.h"

void dump(char* prefix, uint8_t* buffer) {
    printf("%s", prefix);
    for (uint8_t i = 0; i < 16; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}

void simple_test() {
    aes256_keys keys;
    uint8_t seed_key[32];
    uint8_t buffer[16];

    for (uint8_t i = 0; i < sizeof(buffer); i++) {
        buffer[i] = i * 16 + i;
    }
    for (uint8_t i = 0; i < sizeof(seed_key);i++) {
        seed_key[i] = i;
    }

    dump("Text: ", buffer);
    dump("Key: ", seed_key);
    printf("---\n");

    aes256_initialize(&keys, seed_key);
    aes256_encrypt(&keys, buffer);

    dump("Encoding: ", buffer);
    printf("Expected Encoding: 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89\n");

    aes256_initialize(&keys, seed_key);
    aes256_decrypt(&keys, buffer);
    dump("Decrypted: ", buffer);

    aes256_cleanup(&keys);

    for (uint8_t i = 0; i < sizeof(seed_key);i++) {
        seed_key[i] = 0;
    }

    for (uint8_t i = 0; i < sizeof(buffer);i++) {
        buffer[i] = 0;
    }
}

void file_test(char* name) {
    char* copy_expected_command = malloc(strlen(name) + 3 + 15 + 1);
    strcpy(copy_expected_command, "cp ");
    strcat(copy_expected_command, name);
    strcat(copy_expected_command, " ./expected.txt");

    char* copy_encrypted_command = malloc(strlen(name) + 3 + 16 + 1);
    strcpy(copy_encrypted_command, "cp ");
    strcat(copy_encrypted_command, name);
    strcat(copy_encrypted_command, " ./encrypted.txt");

    char* diff_command = malloc(strlen(name) + 5 + 15 + 1);
    strcpy(diff_command, "diff ");
    strcat(diff_command, name);
    strcat(diff_command, " ./expected.txt");

    system(copy_expected_command);

    if (aes256_encrypt_file(name) < 0) {
        printf("Encryption of %s failed.\n", name);
        free(copy_expected_command);
        free(diff_command);
        return;
    }

    system(copy_encrypted_command);

    if (aes256_decrypt_file(name) < 0) {
        printf("Decryption of %s failed.\n", name);
        free(copy_expected_command);
        free(diff_command);
        return;
    }

    system(diff_command);

    free(copy_expected_command);
    free(copy_encrypted_command);
    free(diff_command);
}

int main(int argc, char** argv) {
    // TODO: Use a password (getpass) + SHA-256 to generate the encryption key.
    // TODO: Put the password prompt in aes256_decrypt/encrypt_file.
    // TODO: Modify aes256_decrypt/encrypt_file to no longer take a seed key.

    if (argc > 2 && !strcmp(argv[1], "-f")) {
        file_test(argv[2]);
    } else if (argc == 1) {
        simple_test();
    } else {
        printf("Usage: ./test [-f file]\n");
    }
    return 0;
}
