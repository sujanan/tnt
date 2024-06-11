CC=gcc
CFLAG=-g -Wall

all: tnt

tnt: tnt.o ben.o util.o
	$(CC) $(CFLAG) -o tnt tnt.o ben.o util.o

ben.o: ben.h
util.o: util.h

clean:
	rm -rf tnt *.o
