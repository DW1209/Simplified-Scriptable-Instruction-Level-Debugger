CC = gcc
CFLAGS = -Wall

debugger: main.o sdb.o
	$(CC) $(CFLAGS) $^ -o $@ -lcapstone

%: %.c
	$(CC) $(CFLAGS) -c $^ -lcapstone

clean:
	rm -rf debugger *.o
