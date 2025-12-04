demo: *.c
	$(CC) -Wall -O0 -o demo -include defs.h *.c
