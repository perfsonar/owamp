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
#	Date:		Wed Apr 17 17:53:58 EDT 2002
#
#	Description:	owping build description.

INCLUDES	= $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

bin_PROGRAMS	= owping
owping_SOURCES	= owping.c owpingP.h
owping_LDADD	= $(OWPLIBS) $(I2UTILLIBS) $(MALLOCDEBUGLIBS)
owping_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
