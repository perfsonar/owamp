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
#	Date:		Tue Sep  3 13:06:13 MDT 2002
#
#	Description:	powstream build description.

INCLUDES	= $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

bin_PROGRAMS	= powstream

powstream_SOURCES	= powstream.c powstreamP.h
powstream_LDADD	= $(OWPLIBS) $(I2UTILLIBS)
powstream_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
