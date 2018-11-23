###########
# GENERAL #
###########

all: clean test

CC = gcc -std=c11 -g -ggdb3

O ?= 3

CFLAGS = -Wall -Wextra -pedantic -I../include -O$(O)

############
# COMMANDS #
############

test:
	$(CC) $(CFLAGS) test.c sha256.c -o $@

clean:
	rm -rf *.o test *~ test.dSYM/ .deps/
