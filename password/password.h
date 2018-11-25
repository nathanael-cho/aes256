#ifndef __AES_PASSWORD__
#define __AES_PASSWORD__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include "../infrastructure.h"

#define PASSWORD_LIMIT 128

char* get_password(char* prompt);
// The prompts are built in
char* get_password_with_double_check(void);

#endif
