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
#	Author:		Anatoly Karp
#			Internet2
#
#	Date:		Mon Sep 9 17:53:58 EDT 2002
#
#	Description:	Makefile.am

INCLUDES	= $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

bin_PROGRAMS	 = owdigest
owdigest_SOURCES = owdigest.c 
owdigest_LDADD	 = $(OWPLIBS) $(I2UTILLIBS)
owdigest_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
