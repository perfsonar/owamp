#!/usr/local/bin/perl -wl

# Author: Anatoly Karp, Internet2 (2002)

# Read records <bucket index, bucket count>
# usage: buckets.pl <filename>

use strict;
die "usage: buckets.pl <filename>" unless $ARGV[0];

open FH, $ARGV[0] or die "Could not open $ARGV[0]: $!";
my @stat = stat FH;
die "state failed: $!" if ($#stat == -1);
my $size = $stat[7];
my $num_records;
{
  use integer;
  $num_records = $size / 6;
}
for (my $i = 0; $i < $num_records; $i++) {
  my $buf;
  read FH, $buf, 6 or die "Could not read: $!";
  my ($index, $count) = unpack "LS", $buf;
  print "index = $index, count = $count";
}
