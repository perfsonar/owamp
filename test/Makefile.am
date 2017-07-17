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

check_PROGRAMS  = owtvec owstats owping1
TESTS           = $(check_PROGRAMS)

owtvec_SOURCES	= owtvec.c
owtvec_LDADD	= $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS)
owtvec_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owstats_SOURCES   = owstats.c owtest_utils.c
owstats_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS)
owstats_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owping1_SOURCES   = owping1.c owtest_utils.c
owping1_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
owping1_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
