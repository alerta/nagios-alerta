
AC_PREREQ([2.69])
AC_INIT([alerta-neb], [3.1.1], [nick.satterly@theguardian.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/alerta-neb.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
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

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
