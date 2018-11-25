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

test: clean
	$(CC) $(CFLAGS) test.c aes256.c ../sha256/sha256.c ../password/password.c -o $@

clean:
	rm -rf *.o *~ .deps/ test test.dSYM/
