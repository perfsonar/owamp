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

INCLUDES			= -I$(top_builddir) -I$(top_builddir)/contrib \
				-I$(top_srcdir) -I$(top_srcdir)/contrib \
				$(I2UTILINCS)

bin_PROGRAMS	= owampd
owampd_SOURCES	= owampd.c
owampd_LDADD	= -L$(top_builddir)/owamp -L$(top_builddir)/contrib \
		-lowamp -lowamp_contrib $(I2UTILLIBS)
