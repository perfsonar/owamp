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

INCLUDES	= $(OWPCONTRIBINCS) $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

bin_PROGRAMS	= owping
owping_SOURCES	= owping.c owpingP.h localnode.c localnode.h
owping_LDADD	= $(OWPCONTRIBLIBS) $(OWPLIBS) $(I2UTILLIBS)
owping_DEPENDENCIES = $(OWPCONTRIBLIBDEPS) $(OWPLIBDEPS) $(I2UTILLIBDEPS)
