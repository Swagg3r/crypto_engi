# Flags de compilation
CC=gcc
CFLAGS= -Wall -g
LDFLAGS=

# Exécutables
EXEC=des
SRC= $(wildcard *.c)

.PHONY: clean mrproper

all: $(EXEC)

des: des.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) 

clean:
	rm -f *.o

mrproper: clean
	rm -f $(EXEC)
