#!/usr/local/bin/perl -w

##
##      $Id$
##

# Author: Anatoly Karp, Internet2 (2002)

# Create a histogram of bucket counts from a digest file.
# usage: cookbuckets.pl <filename>

use strict;
use constant DEBUG => 1;

# these are for temporary files
use Fcntl;
use POSIX qw(tmpnam);

# All vesrions of header start with the following fields (all unsigned):
# magic number -  9 bytes
# version      -  1 byte
# header length - 1 byte
# use constant HDR_FIX => 11;
use constant MAGIC_SIZE => 9;
use constant VERSION_SIZE => 1;
use constant HDRSIZE_SIZE => 1;

use constant NUM_LOW => 50000;
use constant NUM_MID  => 1000;
use constant NUM_HIGH => 49900;

use constant CUTOFF_A => (-50.0);
use constant CUTOFF_B => 0.0;
use constant CUTOFF_C => 0.1;
use constant CUTOFF_D => 50.0;

use constant MAX_BUCKET => (NUM_LOW + NUM_MID + NUM_HIGH - 1);
use constant REC_LEN => 8;

my $mesh_low = (CUTOFF_B - CUTOFF_A)/NUM_LOW;
my $mesh_mid = (CUTOFF_C - CUTOFF_B)/NUM_MID;
my $mesh_high = (CUTOFF_D - CUTOFF_C)/NUM_HIGH;

$| = 1;

die "usage: cookbuckets.pl <filename>" unless $ARGV[0];

open FH, $ARGV[0] or die "Could not open $ARGV[0]: $!";

my ($header, $magic, $version, $hdr_len, $prec, $sent, $lost, $dup, $buf);
die "Cannot read magic number" if (read(FH, $magic, MAGIC_SIZE) != MAGIC_SIZE);
$magic = unpack "a8", $magic;

die "Cannot read header" if (read(FH, $buf, VERSION_SIZE + HDRSIZE_SIZE)
			     != VERSION_SIZE + HDRSIZE_SIZE);
($version, $hdr_len) = unpack "CC", $buf;
my $remain_bytes = $hdr_len -  MAGIC_SIZE - VERSION_SIZE - HDRSIZE_SIZE;

die "Currently only work with version 1." unless ($version == 1);
die "Cannot read header" if (read(FH, $buf, $remain_bytes) != $remain_bytes);

($prec, $sent, $lost, $dup) = unpack "CLLL", $buf;

if (DEBUG) {
    print join("\n", "magic = $magic", "version = $version",
	       "hdr_len = $hdr_len", "prec = $prec", "sent = $sent",
	       "lost = $lost", "dup = $dup");
    print "\n";
}

my $name;
#do { $name = tmpnam() }
#        until sysopen(FH, $name, O_RDWR|O_CREAT|O_EXCL);
# warn "created file $name" if DEBUG;
# install atexit-style handler so that when we exit or die,
# we automatically delete this temporary file
# END { unlink($name) or die "Couldn't unlink $name : $!" }

# temporary try:
$name = "gnuplot.dat";
open(OUT, ">$name") or die "Could not open $name";

# die "DEBUG";

my @stat = stat FH;
die "state failed: $!" if ($#stat == -1);
my $size = $stat[7];
my $num_records;
{
  use integer;
  $num_records = ($size - $hdr_len) / REC_LEN;
  print "num_rec = $num_records\n" if DEBUG;
}
for (my $i = 0; $i < $num_records; $i++) {
  my $buf;
  read FH, $buf, REC_LEN or die "Could not read: $!";
  my ($index, $count) = unpack "LL", $buf;
  print "index = $index, count = $count\n";
  print OUT index2pt($index),  " $count\n";
}
close OUT;

my $gnuplot_bin = 'gnuplot';
# set grid
# set nokey
# set size $aa, $bb
# plot "$name" with histeps

open(GNUPLOT, "|$gnuplot_bin") or
  die "gnuplot: $!";
print GNUPLOT <<"STOP";
set terminal png small color

set xlabel "seconds"
set ylabel "bin counts"
set title "Histogram of one-way delays"
set output "buckets.png"
set boxwidth 0.0001
plot "$name" with boxes
STOP
close GNUPLOT;

# convert bucket index to the actual time value
sub index2pt {
    my $index = $_[0];
    die "Index over-run: index = $index" if ($index < 0 
					     or $index > MAX_BUCKET);

    return CUTOFF_A + $index * $mesh_low if $index <= NUM_LOW;

    return CUTOFF_B + ($index - NUM_LOW) * $mesh_mid
		if $index <= NUM_LOW + NUM_MID;

    return CUTOFF_C + ($index - NUM_LOW - NUM_MID) * $mesh_high;
}
