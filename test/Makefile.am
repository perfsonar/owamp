#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2003				#
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
#	Date:		Mon Oct 20 13:52:56 MDT 2003
#
#	Description:	owtvec build description.

INCLUDES	= $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

bin_PROGRAMS	= owtvec
owtvec_SOURCES	= owtvec.c
owtvec_LDADD	= $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS)
owtvec_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
