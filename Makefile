###########
# GENERAL #
###########

all: clean test

CC = gcc -std=c11 -g -ggdb3

O ?= 3

CFLAGS = -Wall -Wextra -pedantic -O$(O)

############
# COMMANDS #
############

test:
	$(CC) $(CFLAGS) test.c aes256.c sha256/sha256.c -o $@

clean:
	rm -rf *.o test *~ test.dSYM/ .deps/ expected.txt encrypted.txt
