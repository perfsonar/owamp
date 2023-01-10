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

AM_CPPFLAGS	= $(OWPINCS) $(I2UTILINCS)
AM_CFLAGS	= $(OWP_PREFIX_CFLAGS)

check_PROGRAMS  = owtvec owstats owping_enc owping_clear owe2e_clear owe2e_auth owe2e_enc twping_enc twping_clear hmac twe2e_clear twe2e_auth twe2e_enc
TESTS           = $(check_PROGRAMS)

owtvec_SOURCES	= owtvec.c
owtvec_LDADD	= $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS)
owtvec_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owstats_SOURCES   = owstats.c owtest_utils.c owtest_utils.h
owstats_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS)
owstats_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owping_clear_SOURCES   = owping_clear.c owtest_utils.c owtest_utils.h server.c server.h session_setup.c session_setup.h
owping_clear_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread -lcrypto
owping_clear_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owping_enc_SOURCES   = owping_enc.c owtest_utils.c owtest_utils.h server.c server.h session_setup.c session_setup.h
owping_enc_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread -lcrypto
owping_enc_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owe2e_clear_SOURCES   = owe2e_clear.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
owe2e_clear_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
owe2e_clear_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owe2e_auth_SOURCES   = owe2e_auth.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
owe2e_auth_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
owe2e_auth_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

owe2e_enc_SOURCES   = owe2e_enc.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
owe2e_enc_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
owe2e_enc_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twping_enc_SOURCES   = twping_enc.c owtest_utils.c owtest_utils.h server.c server.h session_setup.c session_setup.h
twping_enc_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread -lcrypto
twping_enc_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twping_clear_SOURCES   = twping_clear.c owtest_utils.c owtest_utils.h server.c server.h session_setup.c session_setup.h
twping_clear_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread -lcrypto
twping_clear_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twe2e_clear_SOURCES   = twe2e_clear.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
twe2e_clear_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
twe2e_clear_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twe2e_auth_SOURCES   = twe2e_auth.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
twe2e_auth_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
twe2e_auth_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

twe2e_enc_SOURCES   = twe2e_enc.c owtest_utils.c owtest_utils.h e2e_utils.c e2e_utils.h
twe2e_enc_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lpthread
twe2e_enc_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)

hmac_SOURCES   = hmac.c
hmac_LDADD = $(OWPLIBS) -lI2util $(MALLOCDEBUGLIBS) -lcrypto
hmac_DEPENDENCIES = $(OWPLIBDEPS) $(I2UTILLIBDEPS)
