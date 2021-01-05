CC=gcc
MOD_CFLAGS=-fPIC
CFLAGS=-g -O2 -DHAVE_CONFIG_H `pkg-config --cflags glib-2.0`
MOD_LDFLAGS=-shared
LDFLAGS=`pkg-config --libs glib-2.0`
LIBS=-lcurl -ljansson

STRIP=/usr/bin/strip

CP=@CP@

all: nagios3 nagios4 naemon

nagios3: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -I../include $(LIBS) -DNAGIOS3 -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

nagios4: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -I../include $(LIBS) -DNAGIOS4 -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

naemon: alerta-neb.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -I../include $(LIBS) -DNAEMON -o alerta-neb.o alerta-neb.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS)

install:
	[ -d /usr/lib/nagios ] || mkdir /usr/lib/nagios
	install -m 0644 alerta-neb.o /usr/lib/nagios

clean:
	rm -f core *.o
	rm -f *~ *.*~
