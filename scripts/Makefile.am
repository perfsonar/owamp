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
#	Date:		Fri Oct 18 17:53:58 EDT 2002
#
#	Description:	constructing owamp auxiliary files from templates
SUBDIRS = . OWP

noinst_SCRIPTS = owampd.sh collector.pl make_top_html.pl makecron.pl \
		pairs_pages_init.pl powmaster.pl testconf.pl buckets2stats.pl \
		OWP.pm

EXTRA_DIST = owampd.sh.in $(noinst_SCRIPTS)

owampd.sh: owampd.sh.in
	@echo bindir = $(bindir)
	@perl -pe '                                               \
	s!_OWAMPDVARDIR!OWAMPDVARDIR=$(sysconfdir)!;           \
	s!_OWAMPDBINDIR!OWAMPDBINDIR=$(bindir)!;                 \
	s!_CONFDIR!CONFDIR=$(sysconfdir)!                        \
                                                                '\
		< $(srcdir)/owampd.sh.in > owampd.sh	
	chmod +x owampd.sh

clean:
	rm -f owampd.sh
