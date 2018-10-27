#include <stdio.h>

#include "aes256.h"

int main(int argc, char** argv) {
    if (argc > 1) {
        return aes256_encrypt_file(argv[1]);
    }
    printf("Usage: ./encrypt [file]\n");
    return 0;
}
