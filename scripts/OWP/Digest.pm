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
#	File:		OWP::Digest.pm
#
#	Author:		Anatoly Karp
#			Internet2
#
#	Date:		Thu Oct 17 10:40:10  2002
#
#	Description: Merging multiple bucket files.

package OWP::Digest;

require 5.005;
use strict;
use POSIX;

$Digest::REVISION = '$Id$';
$Digest::VERSION='1.0';

# the first 3 fields (all unsigned bytes) are fixed in all versions of header 
use constant MAGIC_SIZE => 9;
use constant VERSION_SIZE => 1;
use constant HDRSIZE_SIZE => 1;

use constant NUM_LOW => 50000;
use constant NUM_MID  => 1000;
use constant NUM_HIGH => 49900;
use constant MAX_BUCKET => (NUM_LOW + NUM_MID + NUM_HIGH - 1);
use constant MAGIC => 'OwDigest';
use constant THOUSAND => 1000;

use constant DEBUG => 1;

# This sub merges @files into a new digest file $newname.
sub merge {
    my ($newname, @files) = @_;

    unless (@files) {
	warn "no files to be merged - continuing...";
	return;
    }

    open OUT, ">$newname" or die "Could not open $newname: $!";

    my @buckets;

    for (0..MAX_BUCKET) {
	$buckets[$_] = 0;
    }

    my ($worst_prec, $final_min) = (64, 99999);
    my ($total_sent, $total_lost, $total_dup) = (0, 0, 0);

    foreach my $file (@files) {
	open(FH, "<$file") or die "Could not open $file: $!";

	my ($header, $prec, $sent, $lost, $dup, $buf, $min, $pre);

	$pre = MAGIC_SIZE + VERSION_SIZE + HDRSIZE_SIZE;
	die "Cannot read header: $!" if (read(FH, $buf, $pre) != $pre);
	my ($magic, $version, $hdr_len) = unpack "a8xCC", $buf;
	my $remain_bytes = $hdr_len - $pre;

	die "Currently only work with version 1: $file" unless ($version == 1);
	die "Cannot read header"
		if (read(FH, $buf, $remain_bytes) != $remain_bytes);
	($prec, $sent, $lost, $dup, $min) = unpack "CLLLL", $buf;

	if ($prec < $worst_prec) {
	    $worst_prec = $prec;
	}

	if ($min < $final_min) {
	    $final_min = $min;
	}

	$total_sent += $sent;
	$total_lost += $lost;
	$total_dup += $dup;

	$min /= THOUSAND; # convert from usec to ms

	# Compute the number of non-empty buckets (== records in the file).
	my @stat = stat FH;
	die "stat failed: $!" unless @stat;
	my $size = $stat[7];
	my ($num_records);
	{
	    use integer;
	    $num_records = ($size - $hdr_len) / 8;
	}

	for (my $i = 0; $i < $num_records; $i++) {
	    my $buf;
	    read FH, $buf, 8 or die "Could not read: $!";
	    my ($index, $count) = unpack "LL", $buf;

	    $buckets[$index] += $count;

	}
	close FH;
    }

    my ($version, $hdrlen) = (1, 28);
    my $header = pack "a8xCCCLLLL", MAGIC, $version, $hdrlen, $worst_prec,
	    $total_sent, $total_lost, $total_dup, $final_min;

    print OUT $header;
    for (my $ind = 0; $ind <= MAX_BUCKET; $ind++) {
	next unless $buckets[$ind];

	my $rec = pack "LL", $ind, $buckets[$ind];
	print OUT $rec;

    }
    close OUT;
}

1;
