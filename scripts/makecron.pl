#!/usr/local/bin/perl -w
#
#      $Id$

# Author: Anatoly Karp, Internet2 (2002)

# This script creates crontab file to run buckets2stats.pl at the right
# frequencies. Default name for the output file is "crontab".

# usage: makecron.pl [crontab_out_file]

use strict;
use constant DEBUG => 1;
use constant VERBOSE => 1;
use constant SECPERMIN => 60;
use constant MINPERHOUR => 60;
use constant HOURSPERDAY => 24;
use FindBin qw($RealBin);
use lib ("$FindBin::Bin");
use OWP;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");
my $outfile = $ARGV[0] || 'crontab';
my $cmd = "$RealBin/buckets2stats.pl";

my @resolutions = $conf->get_val(ATTR=>'DIGESTRESLIST');
open CRON, ">$outfile" or die "Couldn't open $outfile: $!";
select CRON;

foreach my $res (@resolutions) {
    my $min = divide($res, SECPERMIN);
    if ($min <= 59) {
	print "*/$min * * * * $cmd $res 1\n";
	next;
    }

    my $hrs = divide($min, MINPERHOUR);
    if ($hrs <= 23) {
	print "0 */$hrs * * * $cmd $res 1\n";
	next;
    }

    my $days = divide($hrs, HOURSPERDAY);
    if ($days <= 30) {
	print "0 0 * */$days * $cmd $res 1\n";
	next;
    }

    warn "resolution $res too large - skipping";
}

# Add a special command to produce summary data every 5 minutes.
print "*/5 * * * * $cmd 30 2\n";
close CRON;

# Division with rounding up.
sub divide {
    use integer;
    my ($a, $b) = @_;
    die "division by 0!" unless $b;

    return ($a % $b)? ($a/$b) + 1 : $a/$b;
}
