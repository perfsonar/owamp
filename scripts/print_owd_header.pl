#!/usr/bin/perl -w
#
#      $Id$

use strict;

# Author: Anatoly Karp, Internet2 (2002)

# usage: print_owd_header.pl <digest_file>

use strict;

use FileHandle;

use constant THOUSAND => 1000;
use constant MILLION => 1000000;

# the first 3 fields (all unsigned bytes) are fixed in all versions of header 
use constant MAGIC_SIZE => 9;
use constant VERSION_SIZE => 1;
use constant HDRSIZE_SIZE => 1;

# Data for percentile computations.
use constant NUM_LOW => 50000;
use constant NUM_MID  => 10000;
use constant NUM_HIGH => 49900;
use constant CUTOFF_A => (-50.0);
use constant CUTOFF_B => 0.0;
use constant CUTOFF_C => 0.1;
use constant CUTOFF_D => 50.0;
use constant MAX_BUCKET => (NUM_LOW + NUM_MID + NUM_HIGH - 1);
my $mesh_low = (CUTOFF_B - CUTOFF_A)/NUM_LOW;
my $mesh_mid = (CUTOFF_C - CUTOFF_B)/NUM_MID;
my $mesh_high = (CUTOFF_D - CUTOFF_C)/NUM_HIGH;

die "usage: print_owd_header.pl <digestfile>" unless @ARGV == 1;

my $datafile = $ARGV[0];
my $dat_fh = new FileHandle "<$datafile";
die "Could not open $datafile: $!" unless $dat_fh;
my ($sent, $min, $lost,$pairs_ref,$prec) = @{get_buck_ref($dat_fh, $datafile)};
undef $dat_fh;
# print "$datafile: min = $min\n";

sub get_buck_ref {
    my ($fh, $fname) = @_;

    my ($header, $prec, $sent, $lost, $dup, $buf, $min, $pre);

    $pre = MAGIC_SIZE + VERSION_SIZE + HDRSIZE_SIZE;

    die "Cannot read header: $!" if (read($fh, $buf, $pre) != $pre);
    my ($magic, $version, $hdr_len) = unpack "a8xCC", $buf;

    print "hdr_len = $hdr_len\n";

    my $remain_bytes = $hdr_len - $pre;

    die "Currently only work with version 1: $fname" unless ($version == 1);
    die "Cannot read header"
	    if (read($fh, $buf, $remain_bytes) != $remain_bytes);
    ($prec, $sent, $lost, $dup, $min) = unpack "CLLLd", $buf;
    $min *= THOUSAND; # convert from sec to ms
    $min = sprintf "%.3f", $min;
    if (1) {
	 print join "\n", "magic = $magic", "version = $version",
		  "hdr_len = $hdr_len", "prec = $prec", "sent = $sent",
		  "lost = $lost", "dup = $dup", "min = $min ms", '';

#	print "$datafile: prec = $prec\n";
    }

    # Compute the number of non-empty buckets (== records in the file).
    my @stat = stat $fh;
    die "stat failed: $!" unless @stat;
    my $size = $stat[7];
    my $num_records;
    my @pairs = ();
    {
	use integer;
	$num_records = ($size - $hdr_len) / 8;
#	warn "num_rec = $num_records\n" if DEBUG;
    }

    print "Printing the bucket distribution...\n";
    for (my $i = 0; $i < $num_records; $i++) {
	my $buf;
	read $fh, $buf, 8 or die "Could not read: $!";
	my ($index, $count) = unpack "LL", $buf;
	next unless $count;
	my $val = sprintf "%.3f", index2pt($index) * 1000; # sec -> msec
	print "index = $index, count = $count, upper endpoint = $val", " ms\n";
	push @pairs, [$index, $count];
    }

    # Lost packets get "infinite" delay.
#    push @pairs, [MAX_BUCKET, $lost] if $lost;

    return [$sent, $min, $lost, \@pairs, $prec];
}

# convert bucket index to the actual time value
sub index2pt {
    my $index = $_[0] + 1;
    die "Index over-run: index = $index"
	    if ($index < 0 || $index > MAX_BUCKET);

    return CUTOFF_A + $index * $mesh_low if $index <= NUM_LOW;

    return CUTOFF_B + ($index - NUM_LOW) * $mesh_mid
		if $index <= NUM_LOW + NUM_MID;

    return CUTOFF_C + ($index - NUM_LOW - NUM_MID) * $mesh_high;
}
