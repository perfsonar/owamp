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
#	File:		OWP::Utils.pm
#
#	Author:		Anatoly Karp
#			Internet2
#
#	Date:		Wed Oct 2 10:40:10  2002
#
#	Description: Auxiliary subs for large time conversions.

require 5.005;
use strict;
use warnings;
use POSIX;
use Math::BigInt;

package OWP::Utils;

$Utils::REVISION = '$Id$';
$Utils::VERSION='1.0';
$Utils::CONFPATH='~';			# default dir for config files.

use constant JAN_1970 => 0x83aa7e80; # offset in seconds

my $offset_1970 = new Math::BigInt JAN_1970;
my $scale = new Math::BigInt 2**32;

# convert the number of seconds returned by time() into the number
# of seconds since Jan 1, 1970
sub time2time_1970 {
    return $_[0] + JAN_1970;
}

# convert the number of seconds since 1900 to 
sub time_1970totime {
    return $_[0] - JAN_1970;
}

# Convert value return by time() into owamp-style (ASCII form
# of the unsigned 64-bit integer [32.32]
sub time2owptime {
    my $bigtime = new Math::BigInt $_[0];
    $bigtime = time2time_1970($bigtime) * $scale;
    $bigtime =~ s/^\+//;
    return $bigtime;
}

1;
