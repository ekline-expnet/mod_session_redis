AC_PREREQ([2.69])
m4_include([version.m4])
AC_INIT([mod_session_redis], VERSION_NUMBER, [mkj@gotu.dk])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/mod_session_redis.c])
AM_INIT_AUTOMAKE([-Wall])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_CONFIG_HEADERS([src/config.h])

# Check for programs
AC_PROG_CC_STDC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])
AC_CHECK_HEADERS([hiredis/hiredis.h])
AC_CHECK_HEADERS([math.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([floor memmove memset strchr])

AC_ARG_WITH([hiredis-include-path],
        [AS_HELP_STRING([--with-hiredis-include-path],
        [location of hiredis headers, defaults to /usr/include])],
        [HIREDIS_CFLAGS="-I$withval"],
        [HIREDIS_CFLAGS=''])
AC_SUBST([HIREDIS_CFLAGS])

AC_ARG_WITH([hiredis-lib-path],
        [AS_HELP_STRING([--with-hiredis-lib-path],
        [location of hiredis libs, defaults to /usr/lib])],
        [HIREDIS_LIBS="-L$withval -lhiredis"],
        [HIREDIS_LIBS='-lhiredis'])
AC_SUBST([HIREDIS_LIBS])

AC_ARG_WITH([m-include-path],
        [AS_HELP_STRING([--with-m-include-path],
        [location of math headers, defaults to /usr/include])],
        [M_CFLAGS="-I$withval"],
        [M_CFLAGS=''])
AC_SUBST([M_CFLAGS])

AC_ARG_WITH([m-lib-path],
        [AS_HELP_STRING([--with-m-lib-path],
        [location of math libs, defaults to /usr/lib])],
        [M_LIBS="-L$withval -lm"],
        [M_LIBS='-lm'])
AC_SUBST([M_LIBS])

AC_ARG_WITH([apxs],
            [AC_HELP_STRING([--with-apxs=PATH/NAME], [path to the apxs binary [[apxs]]])],
            [AC_SUBST(APXS, $with_apxs)],
            [AC_PATH_PROGS(APXS, [apxs2 apxs])])
AS_IF([test "x${APXS}" != "x" -a -x "${APXS}"],
      [AC_MSG_NOTICE([apxs found at $APXS])
       APXS_LIBEXECDIR=`${APXS} -q LIBEXECDIR`
       AC_SUBST(APXS_LIBEXECDIR)],
      [AC_MSG_FAILURE(["apxs not found. Use --with-apxs"])])


AC_ARG_WITH([apr],
            [AC_HELP_STRING([--with-apr=PATH/NAME], [path to the apr binary [[apr]]])],
            [AC_SUBST(APR, $with_apr)],
            [AC_PATH_PROGS(APR, [apr-1-config])])
AS_IF([test "x${APR}" != "x" -a -x "${APR}"],
      [AC_MSG_NOTICE([apr found at $APR])
       APR_CPPFLAGS=`${APR} --cppflags`
       AC_SUBST(APR_CPPFLAGS)
       APR_INCLUDES=`${APR} --includes`
       AC_SUBST(APR_INCLUDES)
       APR_LDFLAGS=`${APR} --link-libtool --libs`
       AC_SUBST(APR_LDFLAGS)],
      [AC_MSG_FAILURE(["apr-1-config not found. Use --with-apr"])])

PKG_CHECK_MODULES([OPENSSL], [openssl])
AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])


MSR_CFLAGS="`${APXS} -q CFLAGS` `${APXS} -q EXTRA_CPPFLAGS` `${APR} --cflags` ${HIREDIS_CFLAGS} ${M_CFLAGS} ${OPENSSL_CFLAGS} -I`${APXS} -q INCLUDEDIR` `${APR} --includes`"
MSR_LIBS="`${APR} --libs` ${HIREDIS_LIBS} ${M_LIBS} ${OPENSSL_LIBS}"
LIBTOOL="`${APXS} -q LIBTOOL`"
MSR_LIBDIR="`${APXS} -q libexecdir`"

AC_SUBST([MSR_CFLAGS])
AC_SUBST([MSR_LIBS])
AC_SUBST([LIBTOOL])
AC_SUBST([MSR_LIBDIR])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
