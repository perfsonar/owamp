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
# return 0 if the session defined by start/end is not valid.
# otherwise return the index for the "down" of the up/down pair.
# (undefined intervals is an implied index '1' since it will
# presumably be in the first up/down pair that is reported.)
# The index is used to clear out up/down pairs that are no longer
# needed. (Anything before the pair being used can be deleted since
# we expect data to be sent in time order.)
#
sub valid_session{
	my($start,$end,@intervals) = @_;

	# if no pairs defined yet - then the period is assumed valid so far...
	return 1 if(!defined @intervals);

	die "Invalid intervals" unless ($#intervals % 2); # must be pairs

	#
	# invalid <---- up      down
	#               up      down
	#               up      down----->valid
	# start/end pairs are only valid if they can be competely contained
	# between an up/down pair. The last one is a special case in that
	# the down is not really a "down", but a "last message time".
	# (The return 1 after the loop takes care of this case.)
	#
	for(my $i=0;$i<$#intervals;$i+=2){
		return 0 if($start < $intervals[$i]);
		next if($start > $intervals[$i+1]);
		return $i+1 if($end < $intervals[$i+1]);
	}

	return $#intervals;
}

sub get_png_prefix {
    my ($res, $mode) = @_;
    return ($mode == 1)? "$res" : "data-$res";
}

1;
