#!/usr/local/bin/perl -w
#
#      $Id$

use strict;

# Author: Anatoly Karp, Internet2 (2002)

# Read bucket count files, construct time series stats and plot them.
# usage: buckets2stats.pl <dirname> <age_in_hours>

use strict;
use constant DEBUG => 1;
use constant VERBOSE => 1;
use FindBin;
use lib ("$FindBin::Bin");
use OWP;

# these are for temporary files
use Fcntl;
use POSIX qw(tmpnam);

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");

# this directory contains digest files to be processed.
my $datadir = $ARGV[0];

# age is measured in hours
my $age = $ARGV[1];

die "usage: buckets2stats.pl <dirname> <age_in_hours>"
	unless ($datadir && $age);

### Configuration section.
my $digest_suffix = $conf->get_val(ATTR=>'DigestSuffix');

# This files contains gnuplot data and graphs- no reason to have temporary
# files since these just get reused all the time.
my $gnu_dat = "$datadir/gnuplot.dat";
my $gnu_png = "$datadir/gnuplot.png";

### End of configuration section.

use constant TESTING => 0; # XXX - set to 0 eventually
use constant THOUSAND => 1000;

# All versions of header start with the following fields (all unsigned):
# magic number -  9 bytes
# version      -  1 byte
# header length - 1 byte
use constant MAGIC_SIZE => 9;
use constant VERSION_SIZE => 1;
use constant HDRSIZE_SIZE => 1;

use constant MINPERHOUR => 60;
use constant SECPERMIN => 60;

use constant NUM_LOW => 50000;
use constant NUM_MID  => 1000;
use constant NUM_HIGH => 49900;

use constant CUTOFF_A => (-50.0);
use constant CUTOFF_B => 0.0;
use constant CUTOFF_C => 0.1;
use constant CUTOFF_D => 50.0;

use constant MAX_BUCKET => (NUM_LOW + NUM_MID + NUM_HIGH - 1);

my $mesh_low = (CUTOFF_B - CUTOFF_A)/NUM_LOW;
my $mesh_mid = (CUTOFF_C - CUTOFF_B)/NUM_MID;
my $mesh_high = (CUTOFF_D - CUTOFF_C)/NUM_HIGH;

$| = 1;

my @all = split /\n/, `ls $datadir`;
open(GNUDAT, ">>$gnu_dat") or die "Could not open a gnuplot data file";
my $init = time();

foreach my $file (@all) {
    my $sec = is_younger_than($file, 2, $init);

    next unless $sec;
    $sec -= OWP::Utils::JAN_1970;

    my @gm = gmtime($sec);
    my ($second, $minute, $hour, $day, $mon, $year, $wday, $yday) = @gm;
    print join "\n", "sec=$second", "min=$minute", "hour=$hour", 
	    "mon=$mon", "year=$year", '';

    # Read the header.
    open(FH, "<$datadir/$file") or die "Could not open $file: $!";
    my ($header, $prec, $sent, $lost, $dup, $buf, $min, $pre);

    $pre = MAGIC_SIZE + VERSION_SIZE + HDRSIZE_SIZE;
    die "Cannot read header: $!" if (read(FH, $buf, $pre) != $pre);
    my ($magic, $version, $hdr_len) = unpack "a8xCC", $buf;
    my $remain_bytes = $hdr_len - $pre;

    die "Currently only work with version 1: $file" unless ($version == 1);
    die "Cannot read header"
	    if (read(FH, $buf, $remain_bytes) != $remain_bytes);
    ($prec, $sent, $lost, $dup, $min) = unpack "CLLLL", $buf;
    $min /= THOUSAND; # convert from usec to ms
    if (DEBUG) {
	print join("\n", "magic = $magic", "version = $version",
		   "hdr_len = $hdr_len", "prec = $prec", "sent = $sent",
		   "lost = $lost", "dup = $dup", "min = $min");
	print "\n";
    }

    # Compute the number of non-empty buckets (== records in the file).
    my @stat = stat FH;
    die "stat failed: $!" unless @stat;
    my $size = $stat[7];
    my ($num_records, @buckets);
    {
	use integer;
	$num_records = ($size - $hdr_len) / 8;
	print "num_rec = $num_records\n" if DEBUG;
    }

    for (0..MAX_BUCKET) {
	$buckets[$_] = 0;
    }

    for (my $i = 0; $i < $num_records; $i++) {
	my $buf;
	read FH, $buf, 8 or die "Could not read: $!";
	my ($index, $count) = unpack "LL", $buf;
	$buckets[$index] = $count;
    }
    close FH;

    # Compute stats for a new data point.
    my $median = get_percentile(0.5, $sent, \@buckets);
    my $ninety_perc = get_percentile(0.9, $sent, \@buckets);

    my @stats = (get_percentile(0.5, $sent, \@buckets), $min,
		 get_percentile(0.9, $sent, \@buckets));

    print join "\n", 'Stats for the file are:', @stats, '' if VERBOSE;
    print GNUDAT join " ", "$mon/$day/$hour/$minute/$second", @stats, "\n";
}

close GNUDAT;

open(GNUPLOT, "| gnuplot") or die "cannot execute gnuplot";
print GNUPLOT <<"STOP";
set terminal png small color
set xdata time
set format x "%M:%S"
set timefmt "%m/%d/%H/%M/%S"
set nokey
set grid
set xlabel "Time"
set ylabel "Delay (ms)"
set title "One-way delays: Min, Median, and 90th Percentile"
set output "$gnu_png"
plot "$gnu_dat" using 1:2:3:4 with errorbars ps 1
STOP

# convert bucket index to the actual time value
sub index2pt {
    my $index = $_[0];
    die "Index over-run: index = $index"
	    if ($index < 0 || $index > MAX_BUCKET);

    return CUTOFF_A + $index * $mesh_low if $index <= NUM_LOW;

    return CUTOFF_B + ($index - NUM_LOW) * $mesh_mid
		if $index <= NUM_LOW + NUM_MID;

    return CUTOFF_C + ($index - NUM_LOW - NUM_MID) * $mesh_high;
}

# Given a number <alpha> in [0, 1], compute
# min {x: F(x) >= alpha}
# where F is the empirical distribution function (in our case,
# with a fuzz factor due to use of buckets. Multiply the result
# by 1000 to convert from sec to ms.
sub get_percentile {
    my ($alpha, $sent, $bucketref) = @_;
    my $sum = 0;
    my $i;

    unless ((0.0 <= $alpha) && ($alpha <= 1.0)) {
	warn "get_percentile: alpha must be between 0 and 1";
	return undef;
    }

    for ($i = 0; ($i <= MAX_BUCKET) && ($sum < $alpha*$sent); $i++){
	$sum += $bucketref->[$i];
    }
    return index2pt($i)*THOUSAND;
}

# return start time in seconds if the file is younger than a given 
# number of hours
sub is_younger_than {
    my ($filename, $age, $init) = @_;

    $age *= (SECPERMIN * MINPERHOUR); # convert hours to seconds
    return undef unless $filename =~ s/$digest_suffix$//;

    my ($start, $end) = split /_/, $filename;
    my $bigstart = Math::BigInt->new($start);
    my ($sec, $frac_sec) = $bigstart->brsft(32);

    $sec =~ s/^\+//;

    return $sec if TESTING; # XXX - careful!

    my $current = time2time_1970($init);
    return ($current - $start < $age)? $sec : undef;
}

