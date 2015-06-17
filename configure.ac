
AC_PREREQ([2.69])
AC_INIT([alerta-neb], [3.1.1], [nick.satterly@theguardian.com])
AC_CONFIG_SRCDIR([src/alerta-neb.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC
AM_PROG_AR
AC_PROG_RANLIB
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([curl], [curl_easy_perform])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h locale.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h sys/timeb.h syslog.h unistd.h wchar.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostname strncasecmp])

AC_ARG_WITH(nagios, AC_HELP_STRING([--with-nagios], [Path to Nagios files]),
[if test -f "$withval" && test -x "$withval"; then
    NAGIOS_CFLAGS="-I$withval/include"
    NAGIOS_LDFLAGS="-L$withval/lib"
    NAGIOS_LIBS="---???"
fi])

CFLAGS="$CFLAGS $NAGIOS_CFLAGS"
LDFLAGS="$LDFLAGS $NAGIOS_LDFLAGS"
LDFLAGS="$LDFLAGS $NAGIOS_LDFLAGS"

AC_SUBST(NAGIOS_CFLAGS)
AC_SUBST(NAGIOS_LDFLAGS)
AC_SUBST(NAGIOS_LIBS)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
