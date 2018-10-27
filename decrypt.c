#include <stdio.h>

#include "aes256.h"

int main(int argc, char** argv) {
    if (argc > 1) {
        return aes256_decrypt_file(argv[1]);
    }
    printf("Usage: ./decrypt [file]\n");
    return 0;
}
