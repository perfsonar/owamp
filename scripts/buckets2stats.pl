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

# usage: buckets2stats.pl <resolution> [mode]

# The script operates in two modes:
# mode 1 just produces the graphs;
# mode 2 also places a brief summary into a designated file - it can
# be later fetched by make_top_html.pl to fill in values in the
# front page table.

use strict;
use constant DEBUG => 1;
use constant VERBOSE => 1;
use FindBin;
use lib ("$FindBin::Bin");
use IO::Handle;
use File::Path;
use File::Temp qw/ tempfile /;

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

die "Usage: buckets2stats.pl <resolution> [mode]" unless (@ARGV >= 1);
my $res = $ARGV[0]; # current resolution we are working with
my $mode = $ARGV[1] || 1;

$| = 1;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");

my(@mtypes, @nodes, $val, $rec_addr, $send_addr);
@mtypes = $conf->get_val(ATTR=>'MESHTYPES');
@nodes = $conf->get_val(ATTR=>'MESHNODES');
my $dataroot = $conf->{'CENTRALUPLOADDIR'};
my $digest_suffix = $conf->get_val(ATTR=>'DigestSuffix');

open(GNUPLOT, "| gnuplot") or die "cannot execute gnuplot";
autoflush GNUPLOT 1;


my $age = $conf->must_get_val(DIGESTRES=>$res, ATTR=>'PLOTPERIOD');
my $res_name = $conf->must_get_val(DIGESTRES=>$res, ATTR=>'COMMONRESNAME');
my $period_name = $conf->must_get_val(DIGESTRES=>$res, 
				      ATTR=>'PLOT_PERIOD_NAME');

foreach my $mtype (@mtypes){
    foreach my $recv (@nodes){
	$rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	foreach my $sender (@nodes) {
	    next if ($recv eq $sender);	# don't test with self.
	    $send_addr = $conf->get_val(NODE=>$sender, TYPE=>$mtype,
					ATTR=>'ADDR');
	    next unless defined $send_addr;
	    plot_resolution($conf, $mtype, $recv, $sender, $age, $mode);
	}
    }
}

# This sub creates plots for the given combination of parameters.
sub plot_resolution {
    my ($conf, $mtype, $recv, $sender, $age, $mode) = @_;
    my $body = "$mtype/$recv/$sender/$res";
    my ($datadir, $summary_file, $wwwdir) =
	    $conf->get_names_info($mtype, $recv, $sender, $res, $mode);
    my $png_file = get_png_prefix($res, $mode);

    print "plot_resolution: trying datadir = $datadir\n" if VERBOSE;

    unless (-d $datadir) {
	warn "directory $datadir does not exist - skipping";
	return;
    }

    my @all = split /\n/, `ls $datadir`;
    printlist(@all) if DEBUG;

    if (-f $wwwdir) {
	warn "designated directory $wwwdir is a file! - skipping";
	return;
    }

    unless (-d $wwwdir) {
	mkpath([$wwwdir], 0, 0755) or die "Could not create dir $wwwdir: $!";
    }

    my $gnu_dat = "$datadir/$res.dat";
    open(GNUDAT, ">$gnu_dat") or die "Could not open a gnuplot data file";

    my $init = time();
    my $got_data = 0;

    foreach my $file (@all) {
	my $ofile = $file;
	next unless $file =~ s/$digest_suffix$//;

	my $sec = is_younger_than($file, $age, $init);

	next unless $sec;
	$sec -= OWP::Utils::JAN_1970;

	my @gm = gmtime($sec);
	my ($second, $minute, $hour, $day, $mon, $year, $wday, $yday) = @gm;
	warn join " ", "DEBUG: sec=$second", "min=$minute", "hour=$hour",
		"mon=$mon", "year=$year", '' if DEBUG;

	# Read the header.
	my $datafile = "$datadir/$ofile";
	open(FH, "<$datafile") 
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
	if (VERBOSE) {
	    printlist("magic = $magic", "version = $version",
		       "hdr_len = $hdr_len", "prec = $prec", "sent = $sent",
		       "lost = $lost", "dup = $dup", "min = $min");
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

# Suppose the file "data" contains records like

# 03/21/95 10:00  6.02e23

# This file can be plotted by

# set xdata time
#       set timefmt "%m/%d/%y"
#       set xrange ["03/21/95":"03/22/95"]
#       set format x "%m/%d"
#       set timefmt "%m/%d/%y %H:%M"
#       plot "data" using 1:3

# which will produce xtic labels that look like "03/21".

# http://amath.colorado.edu/computing/software/man/gnuplot.html


	my $lost_perc = sprintf "%.3f", ($lost/$sent)*100;
	# Compute stats for a new data point.
	my @stats = map {sprintf "%.3f", $_} 
		(get_percentile(0.5, $sent, \@buckets), $min,
		 get_percentile(0.9, $sent, \@buckets), $lost_perc);

	print join "\n", "Stats for the file $datafile are:",
		@stats, '' if DEBUG;
	print GNUDAT join " ", "$mon/$day/$hour/$minute/$second", @stats, "\n";
	$got_data = 1;

	next if ($mode == 1);

	# Create a plain-text file with data for the last period -
	# it will be picked up by make_top_html.pl to fill entries
	# in its tables.
	my ($tmp_fh, $tmp_name) = tempfile("XXXXXX", DIR => $wwwdir,
					   SUFFIX => "last$res.tmp");
	print $tmp_fh join " ", @stats, "\n";
	close $tmp_fh;

	warn "renaming to newname $summary_file" if DEBUG;
	rename $tmp_name, "$summary_file"
		or die "Could not rename $tmp_name to $summary_file: $!";
    }

    close GNUDAT;
    unless ($got_data) {
	warn "no new data found in $datadir - no plot is done";
	return;
    }

    my $delays_png = "$wwwdir/$png_file-delays.png";
    my $delays_title = "Delays: Min, Median, and 90th Percentile " .
	    "for the last $period_name sampled at $res_name frequency";
    my $loss_png = "$wwwdir/$png_file-loss.png";
    my $loss_title = "Loss percentage " .
	    "for the last $period_name sampled at $res_name frequency";
    my $fmt = $conf->must_get_val(DIGESTRES=>$res, ATTR=>'PLOT_FMT');
    my @tmp = split //, $fmt;
    my $fmt_xlabel = join '/', map {code2unit($_)} @tmp;

    $fmt = join '/', map {"%$_"} split //, $fmt;

#    print "DEBUG: set format x \"$fmt\""; die;

    print GNUPLOT <<"STOP";
set terminal png small color
set xdata time
set format x \"$fmt\"
set timefmt "%m/%d/%H/%M/%S"
set nokey
set grid
set xlabel "Time ($fmt_xlabel)"
set ylabel "Delay (ms)"
set title \"$delays_title\"
set output "$delays_png"
plot "$gnu_dat" using 1:2:3:4 with errorbars ps 1
set ylabel "Loss (%)"
set title \"$loss_title\"
set output "$loss_png"
plot "$gnu_dat" using 1:5 ps 1
STOP

    warn "plotted files: $delays_png $loss_png" if VERBOSE;
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
# number of seconds, and undef otherwise.
sub is_younger_than {
    my ($filename, $age, $init) = @_;

    my ($start, $end) = split /_/, $filename;
    my $bigstart = Math::BigInt->new($start);
    my ($sec, $frac_sec) = $bigstart->brsft(32);

    $sec =~ s/^\+//;

    my $current = OWP::Utils::time2time_1970($init);

    if (DEBUG) {
	my $diff = $current - $start;
	unless ($diff < $age) {
	    warn "DEBUG: diff=$diff, age=$age - skipping $filename";
	}
    }

    return ($current - $start < $age)? $sec : undef;
}

sub printlist {
    print join " ", @_, "\n\n";
}

sub code2unit {
    my $t = $_[0];
    $t eq 'H' && return 'hour';
    $t eq 'M' && return 'minute';
    $t eq 'S' && return 'second';
    $t eq 'd' && return 'day';
    $t eq 'm' && return 'month';
};

