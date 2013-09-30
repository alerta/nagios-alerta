SRC_INCLUDE=../include

CC=gcc
MOD_CFLAGS=-fPIC
CFLAGS=-g -O2 -DHAVE_CONFIG_H
MOD_LDFLAGS=-shared
LDFLAGS=
LIBS= -lcurl

STRIP=/usr/bin/strip

CP=@CP@

all:	alerta-neb.o

alerta-neb.o: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) $(LIBS) -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

clean:
	rm -f core *.o
	rm -f *~ *.*~

