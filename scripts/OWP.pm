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
package OWP;
require 5.005;
require Exporter;
use strict;
use vars qw(@ISA @EXPORT $VERSION);
use OWP::Conf;
use OWP::Utils;

@ISA = qw(Exporter);
@EXPORT = qw(valid_session);

$OWP::REVISION = '$Id$';
$VERSION = '1.0';

#
# return undef if the session defined by start/end is not valid.
# otherwise return 1 for a "valid" session.
# Additionally, this sub deletes any up/downtime pairs before the pair being
# used to validate this particular session since we expect data to be sent in
# time order, the past pairs are no longer useful.
#
sub valid_session{
	my($start,$end,$intervals) = @_;

	# if no pairs defined yet - then the period is assumed valid so far...
	return 1 if(!defined @{$intervals});

	die "Invalid intervals" unless ($#{$intervals} % 2); # must be pairs

	#
	# invalid <---- up      down
	#               up      down
	#               up      down----->valid
	# start/end pairs are only valid if they can be competely contained
	# between an up/down pair. The last one is a special case in that
	# the down is not really a "down", but a "last message time".
	# (The return 1 after the loop takes care of this case.)
	#
	while($#{$intervals} >= 1){
		# start time was before this interval - invalid.
		return undef if($start < ${$intervals}[0]);
		# start time is after this interval - go to next interval.
		next if($start > ${$intervals}[1]);

		# start time is in this interval, if end time is too, then
		# the file is valid.
		
		return 1 if($end < ${$intervals}[1]);

		# if this is the "last" interval, then we tentatively
		# call this valid, but it may be declared invalid later.
		last if($#{$intervals} <= 1);
	}
	continue{
		shift @$intervals; shift @$intervals;
	}

	# should only get here if the session file goes past the
	# last reported uptime interval. In this case, we tentatively
	# call this session valid, but it may be invalidated later.
	return 1;
}

sub get_png_prefix {
    my ($res, $mode) = @_;
    return ($mode == 1)? "$res" : "data-$res";
}

1;
