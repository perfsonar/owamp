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
AC_INIT(owamp, 3.0c, owamp-bugs@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(owamp, 3.0c, [no-define])
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
		AC_HELP_STRING([--with-mallocdebug=<path/MallocDebug.a>],
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

#
# --with-I2Util should probably only be used by developers. Instead
# install the library.
#
AC_ARG_WITH(I2util,
            AC_HELP_STRING([--with-I2util=<path>],
                           [defaults to using installed I2util, use <path> to indicate path to build tree ]),
                           with_I2util=$withval, with_I2util=yes)

if test -n "$with_I2util" -a "$with_I2util" != "yes" -a -d "$with_I2util"; then 
    # Path given for libthrulay
    LDFLAGS="$LDFLAGS -L$with_I2util/I2util"
    CFLAGS="$CFLAGS -I$with_I2util"
    OWPLIBDEPS="$OWPLIBDEPS $with_I2util/I2util/libI2util.a"
fi

AC_SEARCH_LIBS(I2AddrByNode,I2util, ,AC_MSG_ERROR([Couldn't find I2util]))
AC_CHECK_HEADERS([I2util/util.h I2util/conf.h], ,AC_MSG_ERROR([Couldn't find I2util header files]), [AC_INCLUDES_DEFAULT])

OWPINCS='-I${top_srcdir}'

OWP_dir='${top_srcdir}/owamp'
OWPLDFLAGS="-L$OWP_dir"
OWPLIBS="$OWPLDFLAGS -lowamp"
OWPLIBDEPS="$OWP_dir/libowamp.a"

AC_SUBST(OWPINCS)
AC_SUBST(OWPLIBS)
AC_SUBST(OWPLIBDEPS)

AC_SUBST(TOP_BUILD_DIRS)

AC_CANONICAL_HOST
AC_DEFINE(_GNU_SOURCE, 1, "Use glibc features.")
AC_SYS_LARGEFILE
# AC_DEFINE(_LARGEFILE_SOURCE, 1, "Use large file API.")

case $host in
    *-*-solaris* ) 
        AC_DEFINE(__EXTENSIONS__, 1, "get decl for sockaddr_storage on Solaris")
        AC_DEFINE(_XOPEN_SOURCE, 500, "get decl for msg_control on Solaris")
        ;;
esac

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

# This is used for systems that don't provide dirfd()
AC_CHECK_MEMBERS([DIR.d_fd], , ,
	[#include <sys/types.h>
	#include <dirent.h>])

# This is used for systems that don't provide full dirent structure
AC_CHECK_MEMBERS([DIR.d_namlen], , ,
	[#include <sys/types.h>
	#include <dirent.h>])

AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(uint64_t)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)

# Checks for library functions.
AC_FUNC_MALLOC
AC_SEARCH_LIBS(getaddrinfo, [socket nsl])
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socketpair, socket)
AC_SEARCH_LIBS(nanosleep, rt)
AC_SEARCH_LIBS(ceil,m)

AC_CHECK_FUNCS([memset socket bind connect getaddrinfo mergesort dirfd])

# Checks for variable/function declarations.
AC_CHECK_DECLS([optreset])
AC_CHECK_DECLS([fseeko])

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile owamp/Makefile owampd/Makefile owping/Makefile powstream/Makefile conf/Makefile test/Makefile doc/Makefile],
	[test -z "$CONFIG_HEADERS" || echo timestamp > owamp/stamp-h.in])

