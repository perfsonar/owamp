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
#	Date:		Wed Apr 17 13:54:29 EDT 2002
#
#	Description:	libowamp build description.

INCLUDES		= $(OWPINCS)

lib_LIBRARIES		= libowamp.a
libowamp_a_SOURCES	= api.c capi.c sapi.c context.c error.c owampP.h \
			cprotocol.c sprotocol.c io.c \
			endpoint.h endpoint.c time.c \
			arithm128.h arithm128.c \
			rijndael-alg-fst.c rijndael-alg-fst.h \
			rijndael-api-fst.c rijndael-api-fst.h

# Need to rewrite this test slightly before making it a build test...
#TESTS			= rijndael-test-fst
#noinst_PROGRAMS		= rijndael-test-fst
#test_hash_SOURCES	= rijndael-test-fst.c
