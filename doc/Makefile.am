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
		 owping_report.man owping_conn_opts.man owping_out_opts.man \
		 owping_test_opts.man powstream.man
dist_man5_MANS = owampd.conf.man owampd.limits.man owampd.pfs.man
dist_man8_MANS = owampd.man

EXTRA_DIST = index.html details.html owamp_arch.png milestones.html \
	     draft-shalunov-reordering-definition-01.txt



RM = rm -f
man1_LINKS = man1/owping_report.1 man1/owping_conn_opts.1 \
	     man1/owping_out_opts.1 man1/owping_test_opts.1

all-local: man1_link_target

man1:
	@test -z man1 || $(mkdir_p) man1

man1_link_target: man1
	@list='$(man1_LINKS)'; \
	for i in $$list; do \
	   b=`basename $$i .1`; \
	   if ! test -r $$i; then \
	      if test -f $$i; then \
	         rm -f $$i; \
	      fi; \
	      ($(LN_S) ../$$b.man $$i && echo "linking $$i"); \
	   fi; \
	done

distclean-local:
	rm -rf man1

# TODO
# Build html versions of man pages and include them in dist?
# SUFFIXES = .man .man.html
# .man.man.html:
#	man2html -blah_args 
# dist-hook:
SUFFIXES = .man .man.html

.man.man.html:
	cp $< $@

#.man.1: man1
#	echo "$(LN_S) $< $@"; \
#	$(LN_S) $< $@
