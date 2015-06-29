CC = clang -g
SSHINC = -I/usr/local/Cellar/libssh/0.6.3_2/include
SSHLIB = -L/usr/local/Cellar/libssh/0.6.3_2/lib

all: c1
c1: ext.h ext.c c1.c
	$(CC) ext.c c1.c -o c1 -lssh
clean:
	rm -f *.o c1
