CC=gcc
CFLAG=-g -Wall

all: tnt

tnt: tnt.o util.o
	$(CC) $(CFLAG) -o tnt tnt.o util.o 

util.o: util.h

clean:
	rm -rf tnt *.o