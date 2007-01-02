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

dist_man1_MANS = owping.man owstats.man owfetch.man owup.man powstream.man
dist_man5_MANS = owampd.conf.man owampd.limits.man owampd.pfs.man
dist_man8_MANS = owampd.man

# TODO: May be able to autogen html pages during packaging this way...
#BUILT_SOURCES = owping.man.html


# EXTRA_DIST = $(man1_MANS) $(man5_MANS) $(man8_MANS)
EXTRA_DIST = index.html details.html owamp_arch.png milestones.html \
	     draft-shalunov-reordering-definition-01.txt

# TODO
# Build html versions of man pages and include them in dist?
# SUFFIXES = .man .man.html
# .man.man.html:
#	man2html -blah_args 
# dist-hook:
SUFFIXES = .man .man.html

.man.man.html:
	cp $< $@
