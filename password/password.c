#include "password.h"

int fileno();

char* get_password(char* prompt) {
    // To allow for the newline and null characters
    char* password = malloc(sizeof(char) * (PASSWORD_LIMIT + 2));

    struct termios old_flags;
    tcgetattr(fileno(stdin), &old_flags);

    struct termios new_flags = old_flags;
    new_flags.c_lflag &= ~ECHO;
    new_flags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &new_flags)) {
        free(password);
        return NULL;
    }

    printf("%s", prompt);
    if (!fgets(password, PASSWORD_LIMIT + 2, stdin)) {
        zero_array((uint8_t*) password, PASSWORD_LIMIT + 2);
        free(password);
        return NULL;
    }
    password[strlen(password) - 1] = '\0';

    if (tcsetattr(fileno(stdin), TCSANOW, &old_flags)) {
        zero_array((uint8_t*) password, strlen(password));
        free(password);
        return NULL;
    }

    return password;
}

char* get_password_with_double_check(void) {
    char* password = get_password("Password:");
    if (!password) {
        printf("Failed to input a password.\n");
        return NULL;
    }

    char* backup = password;

    password = get_password("Enter password again:");
    if (!password) {
        printf("Failed to input the password a second time.\n");
        zero_array((uint8_t*) backup, (uint8_t) strlen(backup));
        free(backup);
        return NULL;
    }
    if (strcmp(password, backup)) {
        printf("The passwords do not match.\n");
        zero_array((uint8_t*) backup, (uint8_t) strlen(backup));
        zero_array((uint8_t*) password, (uint8_t) strlen(password));
        free(password);
        free(backup);
        return NULL;
    }
    zero_array((uint8_t*) backup, (uint8_t) strlen(backup));
    free(backup);

    return password;
}
