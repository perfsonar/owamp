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
AC_INIT(owamp, 5.0.7, owamp-bugs@internet2.edu)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([no-define foreign])
AC_CONFIG_SRCDIR(owamp/context.c)
AM_CONFIG_HEADER(owamp/config.h)

AC_DEFINE(PATCH_LEVEL, 1, "The RPM version number")
AC_SUBST(PATCH_LEVEL, 1)
 
TOP_BUILD_DIRS=""

AC_ARG_ENABLE(debug,
                [  --enable-debug         turn on debugging],
                [CFLAGS="-g -Wall -DDEBUG $CFLAGS"])

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

OWPINCS='-I${top_srcdir}'

OWP_dir='${top_srcdir}/owamp'
OWPLDFLAGS="-L$OWP_dir"

AC_CHECK_LIB([cap], [cap_set_proc])

OWPLIBS="$OWPLDFLAGS -lowamp"
OWPLIBDEPS="$OWP_dir/libowamp.a"

AC_SUBST(OWPINCS)
AC_SUBST(OWPLIBS)
AC_SUBST(OWPLIBDEPS)

AC_CANONICAL_HOST
AC_DEFINE(_GNU_SOURCE, 1, "Use glibc features.")
AC_SYS_LARGEFILE

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

# musl and uClibc only have adjtimex
AC_CHECK_FUNCS([memset socket bind connect getaddrinfo mergesort dirfd ntp_adjtime adjtimex])

# Checks for variable/function declarations.
AC_CHECK_DECLS([optreset])
AC_CHECK_DECLS([fseeko])

# --with-I2util:
# If not specified, or is 'yes' then:
#       build with local-dir if available
#       use installed otherwise (depends on CFLAGS/LDFLAGS env set correctly)
# If <path> specified, then that <path> must point to an already installed
# prefix style tree (and include/lib subdir is assumed and used to set
# LDFLAGS/CFLAGS
#
AC_ARG_WITH(I2util,
            AC_HELP_STRING([--with-I2util=<path>],
                           [defaults to using sub-dir if avail, otherwise installed. If <path> specified, attempts to use that.]),
                           with_I2util=$withval, with_I2util=yes)

if test \( -z "$with_I2util" -o "$with_I2util" = "yes" \) -a -d I2util; then
    # Use local I2util? - just setup LDFLAGS/CFLAGS so libtool can find
    # it from the Makefile.am during build.
    AC_MSG_WARN([Using local I2util])
    AC_CONFIG_SUBDIRS(I2util)
    TOP_BUILD_DIRS="I2util $TOP_BUILD_DIRS"
    I2util_dir="`pwd`/I2util"
    LDFLAGS="-L$I2util_dir/I2util $LDFLAGS"
    CFLAGS="-I$I2util_dir $CFLAGS"
else
    # else - libI2util must already be built. If <path>, then add to
    # LDFLAGS/CFLAGS - but ultimately, AC_SEARCH_LIBS and AC_CHECK_HEADERS
    # must succeed.
    if test -n "$with_I2util" -a -d "$with_I2util"; then
        I2util_dir="$with_I2util"
        case $I2util_dir in
            /*) ;; # already an absolute path
            *) I2util_dir="`pwd`/$I2util_dir" ;;
        esac
        LDFLAGS="-L$I2util_dir/lib -L$I2util_dir/lib64 $LDFLAGS"
        CFLAGS="-I$I2util_dir/include $CFLAGS"
    fi
    AC_SEARCH_LIBS([I2AddrByNode],I2util, ,AC_MSG_ERROR([Couldn't find I2util library]))
    AC_CHECK_HEADERS([I2util/util.h I2util/conf.h], ,AC_MSG_ERROR([Couldn't find I2util header files]), [AC_INCLUDES_DEFAULT])
fi

# Check for MAN2HTML. The manpages will be compiled to html files if it's
# found.
AC_CHECK_PROGS([MAN2HTML], [man2html])
if test -n "${MAN2HTML}"; then
    AC_DEFINE(MAN2HTML, 1, [MAN2HTML man-page converter])
    do_man2html=true
fi
AM_CONDITIONAL([HAVE_MAN2HTML], test x$do_man2html = xtrue)

AC_SUBST(TOP_BUILD_DIRS)

AC_SUBST(ac_aux_dir)
AC_OUTPUT([Makefile owamp/Makefile owampd/Makefile owping/Makefile powstream/Makefile conf/Makefile test/Makefile doc/Makefile selinux/Makefile],
	[test -z "$CONFIG_HEADERS" || echo timestamp > owamp/stamp-h.in])

