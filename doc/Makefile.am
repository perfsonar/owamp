#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2006				#
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
#	Date:		Sat Feb  4 13:30:20 MST 2006
#
#	Description:

dist_man1_MANS = owping.man owstats.man owfetch.man owup.man \
		 powstream.man twping.man
dist_man5_MANS = owamp-server.conf.man owamp-server.limits.man owamp-server.pfs.man \
	twamp-server.conf.man twamp-server.limits.man twamp-server.pfs.man
dist_man8_MANS = owampd.man twampd.man

EXTRA_DIST = index.html details.html owamp_arch.png milestones.html \
	     draft-shalunov-reordering-definition-02.txt owamp_infosheet.pdf \
	     owping_conn_opts.man owping_report.man owping_out_opts.man \
	     owping_test_opts.man owping.ms owstats.ms owfetch.ms owup.ms

SOELIM=soelim

CLEANFILES	= owping.man owstats.man owfetch.man owup.man \
	owampd.man twampd.man twping.man owamp-server.limits.man \
	twamp-server.limits.man owamp-server.conf.man twamp-server.conf.man

SUFFIXES = .man .ms

.ms.man:
	$(SOELIM) $< > $@

if HAVE_MAN2HTML
SUFFIXES += .man.html
.man.man.html:
	man2html -r $< | grep -v Content-type | sed -e 's/..\/man[0-9]\///g' | sed -e 's/\.[0-9]\.html/.man.html/g' | sed -e 's/\.\.\///g' > $@

EXTRA_DIST += owamp-server.conf.man.html owamp-server.limits.man.html \
	owampd.man.html owamp-server.pfs.man.html owfetch.man.html \
	owping.man.html owping_report.man.html owstats.man.html \
	owup.man.html powstream.man.html twampd.man.html \
	twping.man.html
endif
