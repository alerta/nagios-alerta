CC=gcc
MOD_CFLAGS=-fPIC
CFLAGS=-g -O2 -DHAVE_CONFIG_H
MOD_LDFLAGS=-shared
LDFLAGS=
LIBS= -lcurl

STRIP=/usr/bin/strip

CP=@CP@

nagios3: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -I../include -I../include/nagios3 $(LIBS) -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

nagios4: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -I../include -I../include/nagios4 $(LIBS) -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

install:
	[ -d /usr/lib/nagios ] || mkdir /usr/lib/nagios
	install -m 0644 alerta-neb.o /usr/lib/nagios

clean:
	rm -f core *.o
	rm -f *~ *.*~
