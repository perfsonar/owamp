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
#	File:		OWP.pm
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Tue Sep 24 11:23:49  2002
#
#	Description:	
#
#	Usage:
#
#	Environment:
#
#	Files:
#
#	Options:
use OWP::Conf;
use OWP::Utils;

sub get_png_prefix {
    my ($res, $mode) = @_;
    return ($mode == 1)? "$res" : "data-$res";
}

1;
