#include <stdio.h>
#include <string.h>

#include "password.h"

int main(void) {
    char* password = get_password("Enter password:");
    printf("You typed %s.\n", password);
    free(password);
}
