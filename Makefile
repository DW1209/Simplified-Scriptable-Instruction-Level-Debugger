CC = gcc
CFLAGS = -Wall

hw4: hw4.o sdb.o
	$(CC) $(CFLAGS) $^ -o $@ -lcapstone

%: %.c
	$(CC) $(CFLAGS) -c $^ -lcapstone

clean:
	rm -rf hw4 *.o
