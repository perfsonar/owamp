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
AC_INIT(owamp, 1.0, owamp-bugs@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(owamp, 1.0)
AC_CONFIG_SRCDIR(owamp/context.c)
AM_CONFIG_HEADER(owamp/config.h)

TOP_BUILD_DIRS=""

#
# add configure options.
#
AC_ARG_WITH(I2util,
		AC_HELP_STRING([--with-I2util=<dir>],
				[defaults to building I2util under owamp if exists]),
		with_I2util=$withval, with_I2util=yes)

#
# find I2util
#
I2UTILLDFLAGS=""
I2UTILLIBS=""
I2UTILINCS=""
if test "$with_I2util" != "no"; then
	# first, check for directory given.
	if test "$with_I2util" != "yes"; then
		I2util_dir=`dirname $with_I2util`
		case $I2util_dir in
			/*) ;; # already an absolute path
			*) $I2util_dir="`pwd`/$I2util_dir" ;;
		esac
		I2UTILINCS="-I$I2util_dir/include $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/lib $I2UTILLDFLAGS"
	# now, check for sub-build/sub-configure
	elif test -d I2util/I2util; then
		AC_CONFIG_SUBDIRS(I2util)
		TOP_BUILD_DIRS="I2util $TOP_BUILD_DIRS"
		I2util_dir='${top_srcdir}/I2util'
		I2UTILINCS="-I$I2util_dir $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir/I2util $I2UTILLDFLAGS"
		
	# now, check for installed I2util
	elif test -d /usr/local/I2util; then
		I2UTILINCS="-I/usr/local/I2util/include $I2UTILINCS"
		I2UTILLDFLAGS="-L$I2util_dir $I2UTILLDFLAGS"
	fi

	if test -z "$I2UTILLDFLAGS"; then
		AC_MSG_ERROR([couldn't find I2util library])
	else
		I2UTILLIBS="$I2UTILLDFLAGS -lI2util"
	fi
fi

OWAMP_dir='${top_srcdir}'
OWPINCS="-I$OWAMP_dir"
OWPLDFLAGS="-L$OWAMP_dir/owamp"
OWPLIBS="$OWPLDFLAGS -lowamp"

AC_SUBST(I2UTILINCS)
AC_SUBST(I2UTILLIBS)
AC_SUBST(OWPINCS)
AC_SUBST(OWPLIBS)

AC_SUBST(TOP_BUILD_DIRS)

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([errno.h netdb.h stdlib.h sys/param.h sys/socket.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket getaddrinfo])

# AC_CONFIG_FILES([Makefile owamp/Makefile])

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile owamp/Makefile contrib/Makefile owampd/Makefile \
	 owping/Makefile],
	[test -z "$CONFIG_HEADERS" || echo timestamp > owamp/stamp-h.in])
