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


# 	CENTRALHOST		=>	'netflow.internet2.edu',
# 	CENTRALHOSTUSER		=>	'owamp',
# 	CENTRALUPLOADDIR	=>	'/owamp/upload/',
# 	UPTIMESENDTOADDR	=>	'netflow.internet2.edu',
# 	UPTIMESENDTOPORT	=>	2345,
# 	DATADIR			=>	'/data',
# 	OWAMPDVARPATH		=>	'/var/run',
# 	OWAMPDPIDFILE		=>	'owampd.pid',
# 	OWAMPDINFOFILE		=>	'owampd.info',
# 	UPTIME_DB               =>      'uptime.dat',
# 	OWPBINDIR		=>	"$FindBin::Bin",
# 	CONFDIR			=>	"$Conf::CONFPATH/",

# 	DATADIR			=>	1,
# 	OWAMPDVARPATH		=>	1,
# 	OWPBINDIR		=>	1,
# 	CONFDIR			=>	1,
# 	CENTRALDATADIR		=

SUBDIRS = . OWP

bin_SCRIPTS = owampd.sh collector.pl make_top_html.pl makecron.pl pairs_pages_init.pl powmaster.pl testconf.pl buckets2stats.pl OWP.pm

owampd.sh: owampd.sh.in
	@echo bindir = $(bindir)
	@perl -pe '                                               \
	s!_OWAMPDVARPATH!OWAMPDVARPATH=$(sysconfdir)!;           \
	s!_OWAMPDBINDIR!OWAMPDBINDIR=$(bindir)!;                 \
	s!_DATADIR!DATADIR=/data!;                               \
	s!_CONFDIR!CONFDIR=$(sysconfdir)!                        \
                                                                '\
		< $(srcdir)/owampd.sh.in > owampd.sh	
	chmod +x owampd.sh

clean:
	if test -f owampd.sh; then rm owampd.sh; fi
