#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2002				#
#	     			Internet2				#
#			   All Rights Reserved				#
#									#
#########################################################################
#
#	File:		Makefile.am
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Wed Apr 17 15:11:34 EDT 2002
#
#	Description:	owampd build description

# possible solution to conf dir location
AM_CFLAGS = $(OWP_PREFIX_CFLAGS)

INCLUDES	= $(OWPINCS) $(I2UTILINCS)

bin_PROGRAMS	= owampd twampd
owampd_SOURCES	= owampdP.h owampd.c policy.h policy.c fts.h fts.c
owampd_LDADD	= $(OWPLIBS) $(MALLOCDEBUGLIBS) -lI2util
owampd_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twampd_SOURCES	= owampdP.h twampd.c policy.h policy.c fts.h fts.c
twampd_LDADD	= $(owampd_LDADD)
twampd_DEPENDENCIES = $(owampd_DEPENDENCIES)
