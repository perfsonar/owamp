#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2002				#
#				Internet2				#
#			   All Rights Reserved				#
#									#
#########################################################################
#
#	File:		configure.ac
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Wed Apr 17 13:07:49 EDT 2002
#
#	Description:	autoconfig input script for owamp build
#
#	Usage:		see bootstrap...
#
#	Environment:
#
#	Files:
#
#
#	Options:
# Process this file with autoconf to produce a configure script.
AC_INIT(owamp, 2.0dev-d, owamp-bugs@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(owamp, 2.0dev-d, [no-define])
AC_CONFIG_SRCDIR(owamp/context.c)
AM_CONFIG_HEADER(owamp/config.h)

TOP_BUILD_DIRS=""

#
# add configure options.
#
AC_ARG_WITH(efence,
		AC_HELP_STRING([--with-efence=<path/libefence.a>],
				[yes means use -L/usr/local/lib -lefence]),
		with_efence=$withval, with_efence=no)

AC_ARG_WITH(mallocdebug,
		AC_HELP_STRING([--with-mallocdebug=<path/libefence.a>],
				[yes means use -lMallocDebug]),
		with_mallocdebug=$withval, with_mallocdebug=no)

if test "$with_efence" != "no" -a "$with_mallocdebug" != "no"; then
    AC_MSG_ERROR([--with-efence not valid with --with-mallocdebug]);
fi

#
# setup malloc debugging environment
#
MALLOCDEBUGLIBS=""
if test "$with_efence" != "no"; then
    if test "$with_efence" = "yes"; then
        MALLOCDEBUGLIBS="-L/usr/local/lib -lefence"
    else
        efence_dir=`dirname $with_efence`
        efence_file=`basename $with_efence`
        case $efence_dir in
            /*) ;; # already absolute path
            *) efence_dir="`pwd`/$efence_dir" ;;
        esac
        MALLOCDEBUGLIBS="$efence_dir/$efence_file"
    fi
elif test "$with_mallocdebug" != "no"; then
    if test "$with_mallocdebug" = "yes"; then
        MALLOCDEBUGLIBS="-lMallocDebug"
    else
        mallocdebug_dir=`dirname $with_mallocdebug`
        mallocdebug_file=`basename $with_mallocdebug`
        case $mallocdebug_dir in
            /*) ;; # already absolute path
            *) mallocdebug_dir="`pwd`/$mallocdebug_dir" ;;
        esac
        MALLOCDEBUGLIBS="$mallocdebug_dir/$mallocdebug_file"
    fi
fi
AC_SUBST(MALLOCDEBUGLIBS)

AC_ARG_WITH(I2util,
		AC_HELP_STRING([--with-I2util=<dir>],
				[defaults to building I2util under owamp if exists]),
		with_I2util=$withval, with_I2util=yes)

#
# find I2util
#
I2UTILLDFLAGS=""
I2UTILLIBS=""
I2UTILLIBDEPS=""
I2UTILINCS=""
if test "$with_I2util" != "no"; then
	# first, check for directory given.
	if test "$with_I2util" != "yes"; then
		I2util_dir=`dirname $with_I2util`
		case $I2util_dir in
			/*) ;; # already an absolute path
			*) I2util_dir="`pwd`/$I2util_dir" ;;
		esac
		I2UTILINCS="-I$I2util_dir/include $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/lib $I2UTILLDFLAGS"
		I2UTILLIBDEPS="$I2util_dir/lib/libI2util.a"
	# now, check for sub-build/sub-configure
	elif test -d I2util/I2util; then
		AC_CONFIG_SUBDIRS(I2util)
		TOP_BUILD_DIRS="I2util $TOP_BUILD_DIRS"
		I2util_dir='${top_srcdir}/I2util'
		I2UTILINCS="-I$I2util_dir $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/I2util $I2UTILLDFLAGS"
		I2UTILLIBDEPS="$I2util_dir/I2util/libI2util.a"
		
	# now, check for installed I2util
	elif test -d /usr/local/I2util; then
		I2UTILINCS="-I/usr/local/I2util/include $I2UTILINCS"
		I2UTILLDFLAGS="-L/usr/local/I2util/lib $I2UTILLDFLAGS"
		I2UTILLIBDEPS="/usr/local/I2util/lib/libI2util.a"
	fi

	if test -z "$I2UTILLDFLAGS"; then
		AC_MSG_ERROR([couldn't find I2util library])
	else
		I2UTILLIBS="$I2UTILLDFLAGS -lI2util"
	fi
fi

OWPINCS='-I${top_srcdir}'

OWP_dir='${top_srcdir}/owamp'
OWPLDFLAGS="-L$OWP_dir"
OWPLIBS="$OWPLDFLAGS -lowamp"
OWPLIBDEPS="$OWP_dir/libowamp.a"

AC_SUBST(I2UTILINCS)
AC_SUBST(I2UTILLIBS)
AC_SUBST(I2UTILLIBDEPS)
AC_SUBST(OWPINCS)
AC_SUBST(OWPLIBS)
AC_SUBST(OWPLIBDEPS)

AC_SUBST(TOP_BUILD_DIRS)

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_LN_S

# possible solution to config location
OWP_PREFIX='${prefix}'
OWP_PREFIX_CFLAGS="-DOWP_PREFIX=$OWP_PREFIX"
AC_DEFINE(AUTOCONF_SYSCONFDIR,/etc,"name of sysconfdir under prefix")
AC_SUBST(OWP_PREFIX_CFLAGS)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h netdb.h stdlib.h sys/param.h sys/socket.h sys/time.h sys/types.h sys/mman.h sys/timex.h])

# Checks for typedefs, structures, and compiler characteristics.
I2_C___ATTRIBUTE__
AC_C_CONST
AC_HEADER_TIME
AC_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
	[#include <sys/types.h>
	#include <sys/socket.h>])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket getaddrinfo mergesort])
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socketpair, socket)
AC_SEARCH_LIBS(finite,m)
AC_SEARCH_LIBS(ceil,m)

# Checks for variable/function declarations.
AC_CHECK_DECLS([optreset])
AC_CHECK_DECLS([fseeko])

# AC_CONFIG_FILES([Makefile owamp/Makefile])

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile owamp/Makefile owampd/Makefile owping/Makefile powstream/Makefile conf/Makefile test/Makefile doc/Makefile],
	[test -z "$CONFIG_HEADERS" || echo timestamp > owamp/stamp-h.in])

