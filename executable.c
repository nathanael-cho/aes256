#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "aes256/aes256.h"
#include "sha256/sha256.h"
#include "password/password.h"

// To appease the implicit declaration warnings
int ftruncate();

//////////////////
// FILE HELPERS //
//////////////////

static int ftruncate_wrapper(char*name, int fd, size_t file_size, uint8_t padding) {
    if (ftruncate(fd, file_size - padding) < 0) {
        printf("There are %d extra zero bytes at the end of %s.\n", padding, name);
        return -1;
    }
    return 0;
}

static int get_metadata_fd(char* name, int is_encryption_flag) {
    char* full_path = realpath(name, NULL);
    uint8_t full_path_hash[32];
    get_sha256_hash((uint8_t*) full_path, strlen(full_path), full_path_hash);
    free(full_path);

    char hash_hex[64 + 1];
    for (uint8_t i = 0; i < 32; i++) {
        sprintf(hash_hex + (i * 2), "%02x", full_path_hash[i]);
    }
    zero_array(full_path_hash, 32);
    hash_hex[64] = '\0';

    const char* home_directory = getpwuid(getuid())->pw_dir;
    char* file_name = malloc(strlen(home_directory) + 9 + strlen(hash_hex) + 1);
    strcpy(file_name, home_directory);
    strcat(file_name, "/.hashes/");
    if (is_encryption_flag) {
        IGNORE(mkdir(file_name, S_IRWXU | S_IRGRP | S_IROTH));
    }
    strcat(file_name, hash_hex);
    zero_array((uint8_t*) hash_hex, 64);

    int hash_descriptor = -1;
    if (is_encryption_flag) {
        int file_flags = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        hash_descriptor = open(file_name, O_RDWR | O_CREAT, file_flags);
    } else {
        hash_descriptor = open(file_name, O_RDWR);
    }

    if (hash_descriptor < 0) {
        printf("Could not store the password hash's hash.\n");
        free(file_name);
        return -1;
    }
    free(file_name);

    return hash_descriptor;
}

static int check_metadata_struct_encryption(int hash_descriptor, char* name) {
    file_hash output_content;

    struct stat output_metadata;
    if (fstat(hash_descriptor, &output_metadata) < 0) {
        printf("Could not determine metadata for the output for %s.\n", name);
        close(hash_descriptor);

        return -1;
    }

    size_t output_length = output_metadata.st_size;
    if (output_length >= sizeof(file_hash)) {
        IGNORE(read(hash_descriptor, &output_content, sizeof(file_hash)));
        if (output_content.is_encrypted_flag) {
            printf("%s is already encrypted.\n", name);
            zero_array((uint8_t*) &output_content, sizeof(file_hash));
            close(hash_descriptor);

            return -1;
        }

        zero_array((uint8_t*) &output_content, sizeof(file_hash));
        if (lseek(hash_descriptor, 0, SEEK_SET) < 0) {
            printf("Could not move the output file descriptor back.\n");
            close(hash_descriptor);

            return -1;
        }
    }

    return 0;
}

static int check_metadata_struct_decryption(int fd, char* name, file_hash* stored_hash) {
    ssize_t amount = read(fd, stored_hash, sizeof(file_hash));

    if (amount < (ssize_t) sizeof(file_hash)) {
        printf("Could not read the full hash from disk.\n");
        close(fd);

        return -1;
    }

    if (!(stored_hash->is_encrypted_flag)) {
        printf("%s is not encrypted.\n", name);
        close(fd);

        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        printf("Could not rewind the hash input file's file descriptor.\n");
        close(fd);

        return -1;
    }

    return 0;
}

//////////
// FILE //
//////////

int aes256_encrypt_file(char* name) {
    int fd = open(name, O_RDWR);
    if (fd < 0) {
        printf("Could not open %s.\n", name);
        return -1;
    }

    struct stat metadata;
    if (fstat(fd, &metadata) < 0) {
        printf("Could not determine the size of %s.\n", name);
        close(fd);
        return -1;
    }
    size_t file_size = metadata.st_size;

    uint8_t padding = 16 - (file_size % 16);
    file_size += padding;
    if (ftruncate(fd, file_size) < 0) {
        printf("Could not align file size to a multiple of sixteen.\n");
        close(fd);
        return -1;
    }

    uint8_t* file_data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!file_data) {
        printf("Failed to memory-map %s.\n", name);
        ftruncate_wrapper(name, fd, file_size, padding);
        close(fd);
        return -1;
    }
    file_data[file_size - 1] = padding;

    char* password = get_password_with_double_check();
    if (!password) {
        // Errors already handled and printed
        ftruncate_wrapper(name, fd, file_size, padding);
        munmap(file_data, file_size);
        close(fd);
        return -1;
    }

    uint8_t seed_key[32];
    get_sha256_hash((uint8_t*) password, (uint8_t) strlen(password), seed_key);
    zero_array((uint8_t*) password, (uint8_t) strlen(password));
    free(password);

    int hash_descriptor = get_metadata_fd(name, 1);
    if (hash_descriptor < 0) {
        // Errors already handled and printed
        zero_array(seed_key, 32);
        ftruncate_wrapper(name, fd, file_size, padding);
        munmap(file_data, file_size);
        close(fd);

        return -1;
    }

    // FEATURE: Encrypt the metadata files.

    if (check_metadata_struct_encryption(hash_descriptor, name) < 0) {
        // The file descriptor is already closed
        zero_array(seed_key, 32);
        ftruncate_wrapper(name, fd, file_size, padding);
        munmap(file_data, file_size);
        close(fd);

        return -1;
    }

    file_hash output_content;

    get_sha256_hash(seed_key, 32, output_content.hash);
    output_content.is_encrypted_flag = 1;
    IGNORE(write(hash_descriptor, &output_content, sizeof(file_hash)));
    close(hash_descriptor);
    zero_array(output_content.hash, 32);

    aes256_keys keys;

    uint8_t buffer[16] = {0};
    for (size_t file_pointer = 0; file_pointer < file_size; file_pointer += 16) {
        copy_array(buffer, file_data + file_pointer, 16);

        aes256_initialize(&keys, seed_key);
        aes256_encrypt(&keys, buffer);

        copy_array(file_data + file_pointer, buffer, 16);
    }

    zero_array(buffer, 16);
    aes256_cleanup(&keys);
    zero_array(seed_key, 32);

    munmap(file_data, file_size);
    close(fd);

    return 0;
}

int aes256_decrypt_file(char* name) {
    int fd = open(name, O_RDWR);
    if (fd < 0) {
        printf("Could not open %s.\n", name);
        return -1;
    }

    struct stat metadata;
    if (fstat(fd, &metadata) < 0) {
        printf("Could not determine the size of %s.\n", name);
        close(fd);
        return -1;
    }
    size_t file_size = metadata.st_size;
    if (file_size % 16) {
        printf("There was a file size error with the encryption of %s.\n", name);
        close(fd);
        return -1;
    }

    uint8_t* file_data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!file_data) {
        printf("Failed to memory-map %s.\n", name);
        close(fd);
        return -1;
    }

    char* password = get_password("Password:");
    if (!password) {
        printf("Failed to input a password.\n");
        munmap(file_data, file_size);
        close(fd);
        return -1;
    }

    uint8_t seed_key[32];
    get_sha256_hash((uint8_t*) password, strlen(password), seed_key);
    zero_array((uint8_t*) password, (uint8_t) strlen(password));
    free(password);

    char* full_path = realpath(name, NULL);
    uint8_t full_path_hash[32];
    get_sha256_hash((uint8_t*) full_path, strlen(full_path), full_path_hash);
    free(full_path);

    int hash_descriptor = get_metadata_fd(name, 0);
    if (hash_descriptor < 0) {
        // Errors taken care of
        zero_array(seed_key, 32);
        munmap(file_data, file_size);
        close(fd);

        return -1;
    }

    file_hash stored_hash;
    if (check_metadata_struct_decryption(hash_descriptor, name, &stored_hash) < 0) {
        // Descriptor already closed
        zero_array((uint8_t*) &stored_hash, sizeof(file_hash));

        zero_array(seed_key, 32);
        munmap(file_data, file_size);
        close(fd);

        return -1;
    }

    uint8_t hash_hash[32];
    get_sha256_hash(seed_key, 32, hash_hash);

    if (strncmp((char*) stored_hash.hash, (char*) hash_hash, 32)) {
        printf("The hash does not correspond to the stored hash.\n");
        close(hash_descriptor);
        zero_array(seed_key, 32);
        zero_array((uint8_t*) &stored_hash, sizeof(file_hash));
        zero_array(hash_hash, 32);
        munmap(file_data, file_size);
        close(fd);

        return -1;
    }

    stored_hash.is_encrypted_flag = 0;
    IGNORE(write(hash_descriptor, &stored_hash, sizeof(file_hash)));
    close(hash_descriptor);

    zero_array((uint8_t*) &stored_hash, sizeof(file_hash));
    zero_array(hash_hash, 32);

    aes256_keys keys;

    uint8_t buffer[16] = {0};
    for (size_t file_pointer = 0; file_pointer < file_size; file_pointer += 16) {
        copy_array(buffer, file_data + file_pointer, 16);

        aes256_initialize(&keys, seed_key);
        aes256_decrypt(&keys, buffer);

        copy_array(file_data + file_pointer, buffer, 16);
    }

    zero_array(buffer, 16);
    aes256_cleanup(&keys);
    zero_array(seed_key, 32);

    uint8_t padding = file_data[file_size - 1];
    if (ftruncate(fd, file_size - padding) < 0) {
        printf("There are %d extra zero bytes at the end of %s.\n", padding, name);
    }

    munmap(file_data, file_size);
    close(fd);

    return 0;
}

//////////
// MAIN //
//////////

int main(int argc, char** argv) {
    #ifdef IS_ENCRYPTION_FLAG
    if (IS_ENCRYPTION_FLAG) {
        if (argc > 1) {
            return aes256_encrypt_file(argv[1]);
        }
        printf("Usage: ./encrypt [file]\n");
        return 0;
    } else {
        if (argc > 1) {
            return aes256_decrypt_file(argv[1]);
        }
        printf("Usage: ./decrypt [file]\n");
        return 0;
    }
    #else
    // Default to encryption
    if (argc > 1) {
        return aes256_encrypt_file(argv[1]);
    }
    printf("Usage: ./encrypt [file]\n");
    return 0;
    #endif
}
