#!/usr/local/bin/perl -w
#
#      $Id$

use strict;

# Author: Anatoly Karp, Internet2 (2002)

# This script accepts a resolution, fetches look-back period,
# and constructs plots for all node pairs. The resolution itself
# and its associated attributes MUST be defined in the config
# file so that they can be fetched. Resulting plots are placed
# under $conf->{'CENTRALWWWDIR'}

# usage: buckets2stats.pl <resolution>

use strict;
use constant DEBUG => 1;
use constant VERBOSE => 1;
use FindBin;
use lib ("$FindBin::Bin");
use IO::Handle;
use File::Path;
use OWP;

use constant TESTING => 0; # XXX - set to 0 eventually
use constant THOUSAND => 1000;

# the first 3 fields (all unsigned bytes) are fixed in all versions of header 
use constant MAGIC_SIZE => 9;
use constant VERSION_SIZE => 1;
use constant HDRSIZE_SIZE => 1;

# Data for percentile computations.
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

die "Usage: buckets2stats.pl <resolution>" unless (@ARGV == 1);
my $res = $ARGV[0]; # current resolution we are working with

$| = 1;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");

my(@mtypes, @nodes, $val, $rec_addr, $send_addr);
@mtypes = $conf->get_val(ATTR=>'MESHTYPES');
@nodes = $conf->get_val(ATTR=>'MESHNODES');
my $dataroot = $conf->{'CENTRALUPLOADDIR'};
my $digest_suffix = $conf->get_val(ATTR=>'DigestSuffix');
my $wwwdir = $conf->{'CENTRALWWWDIR'};

# my @reslist = $conf->get_val(ATTR=>'DIGESTRESLIST');
# print $conf->dump;

open(GNUPLOT, "| gnuplot") or die "cannot execute gnuplot";
autoflush GNUPLOT 1;

my $age = $conf->must_get_val(DIGESTRES=>$res, ATTR=>'PLOTPERIOD');

foreach my $mtype (@mtypes){
    foreach my $recv (@nodes){
	$rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	foreach my $sender (@nodes) {
	    next if ($recv eq $sender);	# don't test with self.
	    $send_addr = $conf->get_val(NODE=>$sender, TYPE=>$mtype,
					ATTR=>'ADDR');
	    next unless defined $send_addr;
	    my $body = "$mtype/$recv/$sender/$res";
	    plot_resolution($dataroot, $body, $age,
			    "$wwwdir/$body", "$res.png");
	}
    }
}

sub plot_resolution {
    my ($prefix, $body, $age, $outdir, $outfile) = @_;
    printlist(@_);
    my $datadir = "$prefix/$body";
    print "datadir = $datadir\n";
    my @all = split /\n/, `ls $datadir`;
    printlist(@all);

    if (-f $outdir) {
	warn "designated directory $outdir is a file! - skipping";
	return;
    }

    unless (-d $outdir) {
	mkpath([$outdir], 0, 0755) or die "Could not create dir $outdir: $!";
    }

    my $gnu_dat = "$datadir/$res.dat";
    open(GNUDAT, ">>$gnu_dat") or die "Could not open a gnuplot data file";

    my $init = time();
    my $got_data = 0;

    foreach my $file (@all) {
	my $ofile = $file;
	next unless $file =~ s/$digest_suffix$//;

	my $sec = is_younger_than($file, 2, $init);

	next unless $sec;
	$sec -= OWP::Utils::JAN_1970;

	my @gm = gmtime($sec);
	my ($second, $minute, $hour, $day, $mon, $year, $wday, $yday) = @gm;
	warn join "\n", "sec=$second", "min=$minute", "hour=$hour",
		"mon=$mon", "year=$year", '' if DEBUG;

	# Read the header.
	open(FH, "<$datadir/$ofile") 
		or die "Could not open $datadir/$ofile: $!";
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
	$got_data = 1;
    }

    close GNUDAT;
    unless ($got_data) {
	warn "no new data found in $prefix/$body - no plot is done";
	return;
    }

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
set output "$outdir/$outfile"
plot "$gnu_dat" using 1:2:3:4 with errorbars ps 1
STOP

}

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
# number of seconds
sub is_younger_than {
    my ($filename, $age, $init) = @_;

    my ($start, $end) = split /_/, $filename;
    my $bigstart = Math::BigInt->new($start);
    my ($sec, $frac_sec) = $bigstart->brsft(32);

    $sec =~ s/^\+//;

    return $sec if TESTING; # XXX - careful!

    my $current = OWP::Utils::time2time_1970($init);
    return ($current - $start < $age)? $sec : undef;
}

sub printlist {
    print join " ", @_, "\n\n";
}
