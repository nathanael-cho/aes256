###########
# GENERAL #
###########

all: clean encrypt decrypt

CC = gcc -std=c11 -g -ggdb3

O ?= 3

CFLAGS = -Wall -Wextra -pedantic -O$(O)

############
# COMMANDS #
############

encrypt:
	$(CC) $(CFLAGS) encrypt.c aes256/aes256.c sha256/sha256.c password/password.c -o $@

decrypt:
	$(CC) $(CFLAGS) decrypt.c aes256/aes256.c sha256/sha256.c password/password.c -o $@

clean:
	rm -rf *.o encrypt decrypt *~ encrypt.dSYM/ decrypt.dSYM/ .deps/ encrypted.txt expected.txt aes256/*~ sha256/*~ password/*~ include/*~
