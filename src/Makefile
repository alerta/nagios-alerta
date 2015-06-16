INC_NAGIOS3=../include/nagios3
INC_NAGIOS4=../include/nagios4

CC=gcc
MOD_CFLAGS=-fPIC
CFLAGS=-g -O2 -DHAVE_CONFIG_H
MOD_LDFLAGS=-shared
LDFLAGS=
LIBS= -lcurl

STRIP=/usr/bin/strip

CP=@CP@

all:	alerta-neb-3x alerta-neb-4x

alerta-neb-3x: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) $(INC_NAGIOS3) -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

alerta-neb-4x: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) $(INC_NAGIOS4) -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

install:
	install -m 0644 alerta-neb.o /usr/local/lib

clean:
	rm -f core *.o
	rm -f *~ *.*~

