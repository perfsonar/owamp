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

INCLUDES	= $(OWPCONTRIBINCS) $(OWPINCS) $(I2UTILINCS)

bin_PROGRAMS	= owampd
owampd_SOURCES	= owampd.c
owampd_LDADD	= $(OWPLIBS) $(OWPCONTRIBLIBS)  $(I2UTILLIBS)
owampd_DEPENDENCIES = $(OWPCONTRIBLIBDEPS) $(OWPLIBDEPS) $(I2UTILLIBDEPS)
