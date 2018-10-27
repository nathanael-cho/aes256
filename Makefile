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

simple_test: clean
	$(CC) $(CFLAGS) simple_test.c aes256.c sha256/sha256.c -o $@

clean:
	rm -rf *.o encrypt decrypt *~ encrypt.dSYM/ decrypt.dSYM/ .deps/ encrypted.txt expected.txt simple_test simple_test.dSYM/
