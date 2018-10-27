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
	$(CC) $(CFLAGS) encrypt.c aes256.c sha256/sha256.c -o $@

decrypt:
	$(CC) $(CFLAGS) decrypt.c aes256.c sha256/sha256.c -o $@

test: clean
	$(CC) $(CFLAGS) test.c aes256.c sha256/sha256.c -o $@

clean:
	rm -rf *.o encrypt decrypt *~ encrypt.dSYM/ decrypt.dSYM/ .deps/ encrypted.txt expected.txt test test.dSYM/
