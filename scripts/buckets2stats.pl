#!/usr/bin/perl -w
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

use constant ARCHIVE_DEBUG => 0;

use constant DEBUG => 0;
use constant VERBOSE => 0;

use FindBin;
use lib ("$FindBin::Bin");
use IO::Handle;
use File::Path;
use File::Temp qw/ tempfile /;
use Fcntl qw(:flock);
use FileHandle;

use OWP::Syslog;
use OWP::Digest;

use OWP;

use constant TESTING => 0; # XXX - set to 0 eventually

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

die "Usage: buckets2stats.pl <resolution> [mode]" unless (@ARGV >= 1);
my $res = $ARGV[0]; # current resolution we are working with
my $mode = $ARGV[1] || 1;

$| = 1;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");
# setup syslog

local(*MYLOG);
my $slog = tie *MYLOG, 'OWP::Syslog',
		facility	=> $conf->must_get_val(ATTR=>'SyslogFacility'),
		log_opts	=> 'pid',
		setlogsock	=> 'unix';
# make die/warn goto syslog, and also to STDERR.
my $run_cmd_line = 0;
if ($run_cmd_line) {
    my $errfh = \*STDERR;
    $slog->HandleDieWarn($errfh);
} else {
    $slog->HandleDieWarn();
}
undef $slog;	# Don't keep tie'd ref's around unless you need them...

my(@mtypes, @nodes, $val, $rec_addr, $send_addr);
@mtypes = $conf->get_val(ATTR=>'MESHTYPES');
@nodes = $conf->get_val(ATTR=>'MESHNODES');
my $dataroot = $conf->{'CENTRALDATADIR'};
my $digest_suffix = $conf->get_val(ATTR=>'DigestSuffix');
my $summ_period = $conf->get_val(ATTR => 'SUMMARY_PERIOD') || 300;

open(GNUPLOT, "| gnuplot") or die "cannot execute gnuplot";
autoflush GNUPLOT 1;

my $age = $conf->must_get_val(DIGESTRES => $res, ATTR => 'PLOTPERIOD');
my $res_name = $conf->must_get_val(DIGESTRES => $res, ATTR => 'COMMONRESNAME');
my $period_name = $conf->must_get_val(DIGESTRES => $res,
				      ATTR => 'PLOT_PERIOD_NAME');
my $vtimefile = $conf->must_get_val(ATTR => 'CentralPerDirValidFile');
my $inf_coef = $conf->get_val(ATTR => 'INF_DELAY_MULT') || 1.5;

my ($cur_min, $cur_hour) = (gmtime(time()))[1, 2];
my $time_to_archive = (($cur_min >= 58) || ($cur_min <= 2))? 1: 0;

foreach my $mtype (@mtypes){
    foreach my $recv (@nodes){
	$rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	foreach my $sender (@nodes) {
	    next if ($recv eq $sender);	# don't test with self.
	    $send_addr = $conf->get_val(NODE=>$sender, TYPE=>$mtype,
					ATTR=>'ADDR');
	    next unless defined $send_addr;

	    # Recover the last validated time
	    my $dir = "$dataroot/$mtype/$recv/$sender";
	    warn "trying $dir" if DEBUG;
	    my $end;
	    if (open TFILE, "<$dir/$vtimefile") {
		$end = <TFILE>;
		close TFILE;
		chomp $end;
	    } else {
		warn "Open Error $dir/$vtimefile: $!" if 0;
	    }

	    if ($mode == 1) {
		plot_resolution($conf, $mtype, $recv, $sender, $age);
	    } else { # make_summary($summ_period)
		# Create a plain-text file with data for the last period -
		# it will be picked up by make_top_html.pl to fill entries
		# in its tables.

		my ($datadir, $summary_file, undef) =
			$conf->get_names_info($mtype, $recv, $sender, $res,
					      $mode);
		unless (-d $datadir) {
		    warn "directory $datadir does not exist - skipping";
		    return;
		}

		my $fh = new FileHandle $summary_file, O_RDWR|O_CREAT;
		unless ($fh) {
		    warn "Could not open $summary_file: $!";
		    next;
		}

		next unless flock($fh, LOCK_EX);
		# compute stats here
		warn "plot_resolution: trying datadir = $datadir" if VERBOSE;

		my @all = split /\n/, `ls $datadir`;
		my $init = time();

		my $got_data = 0;
		my ($worst_median_delay, $worst_loss) = (0.0, 0.0);
		foreach my $file (@all) {
		    my $ofile = $file;
		    next unless $file =~ s/$digest_suffix$//;

		    my $sec = is_younger_than($file, $summ_period, $init);

		    next unless $sec;
		    $sec -= OWP::Utils::JAN_1970;
		    my ($year, $mon, $day, $hour, $minute, $second)
			    = ymdHMS($sec);

		    my $datafile = "$datadir/$ofile";
		    my $dat_fh = new FileHandle "<$datafile";
		    die "Could not open $datafile: $!" unless $dat_fh;
		    my ($sent, $min, $lost, $pairs_ref, $prec) =
			    @{get_buck_ref($dat_fh, $datafile)};
		    undef $dat_fh;

		    unless ($sent) {
			warn "sent == 0 in $datafile - skipping";
			next;
		    }
		    my $lost_perc = ($lost/$sent)*100.0;

		    # Compute stats for a new data point.
		    my $median = get_percentile(0.5, $sent, $pairs_ref, $lost);
		    $worst_loss = $lost_perc if ($lost_perc > $worst_loss);
		    $worst_median_delay = $median
			    if ($median > $worst_median_delay);

		    $got_data = 1;
		}

		($worst_median_delay, $worst_loss) = map {sprintf "%.2f", $_}
			($worst_median_delay, $worst_loss);

		my $out = ($got_data)? 
			join " ", $worst_median_delay, $worst_loss, "\n" :
				"* *\n";
		print $fh $out;
		close $fh;
	    }
	}
    }
}

close GNUPLOT;

# This sub creates plots for the given combination of parameters.
sub plot_resolution {
    my ($conf, $mtype, $recv, $sender, $age) = @_;
    my $body = "$mtype/$recv/$sender/$res";
    my ($datadir, $summary_file, $wwwdir) =
	    $conf->get_names_info($mtype, $recv, $sender, $res);
    my $png_file = $res;
    my $archive_png = ($time_to_archive && ($res == 30))? 1 : 0;

    $archive_png = 1 if ARCHIVE_DEBUG;

    warn "plot_resolution: trying datadir = $datadir" if VERBOSE;

    unless (-d $datadir) {
	warn "directory $datadir does not exist - skipping";
	return;
    }

    my $archive_dir = "$datadir/png_archive";

    my @all = split /\n/, `ls $datadir`;

    if (-f $wwwdir) {
	warn "designated directory $wwwdir is a file! - skipping";
	return;
    }

    unless (-d $wwwdir) {
	mkpath([$wwwdir], 0, 0755) or die "Could not create dir $wwwdir: $!";
    }

    if ($archive_png) {
	   if (-f $archive_dir) {
	       warn "designated directory $archive_dir is a file! - skipping";
	       return;
	   }

	   unless (-d $archive_dir) {
	       mkpath([$archive_dir], 0, 0755)
		       or die "Could not create dir $archive_dir: $!";
	   }
    }

    my $gnu_dat = "$datadir/$res.dat";
    open(GNUDAT, ">$gnu_dat") or die "Could not open $gnu_dat: $!";
    autoflush GNUDAT 1;
    unless (flock(GNUDAT, LOCK_EX)) {
	warn "Could not flock $gnu_dat: $!";
	close GNUDAT;
	return;
    }

    my $gnu_inf_med = "$datadir/$res.inf-med";
    open(GNU_INF_MED, ">$gnu_inf_med")
	    or die "Could not open $gnu_inf_med: $!";
    autoflush GNU_INF_MED 1;
    my $got_inf_med = 0;

    my $gnu_inf_ninety = "$datadir/$res.inf-ninety";
    open(GNU_INF_NINETY, ">$gnu_inf_ninety")
	    or die "Could not open $gnu_inf_ninety: $!";
    autoflush GNU_INF_NINETY 1;
    my $got_inf_ninety = 0;

    my $init = time();
    my ($y, $M, $d, $h, $m, $s, $xr_end, $xr_start, $archived_prefix);

    # Prepare start/end times needed for later developments.
    if ($archive_png) {
	($y, $M, $d, $h, $m, $s) = ymdHMS($init - $age);
	$xr_start = join '/', $y, $m, $d, $h, $m, $s;
	$h += sprintf "%.0f", ($m / 60.0);
	$archived_prefix = "$archive_dir/" . join '.', $y, $M, $d, $h;
	($y, $M, $d, $h, $m, $s) = ymdHMS($init);
	$xr_end = join '/', $y, $M, $d, $h, $m, $s;
    } else {
	$xr_end = join '/', ymdHMS($init);
	$xr_start = join '/', ymdHMS($init - $age);
    }

    my $got_data = 0;
    my $worst_prec = 64;

    foreach my $file (@all) {
	my $ofile = $file;
	next unless $file =~ s/$digest_suffix$//;

	my $sec = is_younger_than($file, $age, $init);

	next unless $sec;
	$sec -= OWP::Utils::JAN_1970;

	my ($year, $mon, $day, $hour, $minute, $second) = ymdHMS($sec);

	my $datafile = "$datadir/$ofile";
	my $dat_fh = new FileHandle "<$datafile";
	die "Could not open $datafile: $!" unless $dat_fh;
	my ($sent, $min, $lost, $pairs_ref, $prec) =
		@{get_buck_ref($dat_fh, $datafile)};
	undef $dat_fh;

	$worst_prec = $prec if $prec < $worst_prec;

	print "DEBUG: loop: worst_prec = $worst_prec\n" if DEBUG;

	unless ($sent) {
	    warn "sent == 0 in $datafile - skipping";
	    next;
	}

	my $lost_perc = fmt(($lost/$sent)*100);

	my ($med, $perc_ninety) =
		(get_percentile(0.5, $sent, $pairs_ref, $lost),
		 get_percentile(0.9, $sent, $pairs_ref, $lost));

	# Fetch index of the last non-empty bucket.
	my $inf = index2pt(${$pairs_ref}[-1]->[0]) * $inf_coef;
	$inf ||= 50;

	# Plotting is done in 2 layers. Infinities are placed in
	# a separate file.
	my @stats = (($med eq 'inf')? $min : fmt($med),
		     $min,
		     ($perc_ninety eq 'inf')? $min : fmt($perc_ninety),
		     $lost_perc);

	my $date = "$year/$mon/$day/$hour/$minute/$second";
	print GNUDAT join " ", $date, @stats, "\n";
	$got_data = 1;

	if ($med eq 'inf') {
	    print GNU_INF_MED join " ", $date, $inf, "\n";
	    $got_inf_med = 1;
	}
	if ($perc_ninety eq 'inf') {
	    print GNU_INF_NINETY join " ", $date, $inf, "\n";
	    $got_inf_ninety = 1;
	}
    }

    # Compute the worst error in usec's
    my $err = ((2**(32 - $worst_prec)) * 2) * THOUSAND;

    close GNU_INF_MED;
    close GNU_INF_NINETY;

    my ($psize, $err_line);

    if ($got_data) {
	$psize = 1;
	$err_line = "Max error $err ms.";
#	$err_line = "set key right top title \"Max error $err usec.\"";
	print "DEBUG: worst_prec = $worst_prec\n" if DEBUG;
    } else {
	warn "no new data found in $datadir - creating an empty plot";
	print GNUDAT join '/', ymdHMS($init - 0.5*$age);
	print GNUDAT ' ', join ' ', 0, 0, 0, 0, 0, "\n";
	$psize = 0.0;
	$err_line = '';
	print "DEBUG: no data for the $sender -> $recv\n" if DEBUG;
    }

    warn "err_line = $err_line" if DEBUG;

    my $delays_png = "$wwwdir/$png_file-delays.png";
    my $delays_title = "Delays: Min, Median, and 90th Percentile " .
	    "for the last $period_name. $err_line";
#	    "for the last $period_name sampled at $res_name frequency";
    my $loss_png = "$wwwdir/$png_file-loss.png";
    my $loss_title = "Loss percentage " .
	    "for the last $period_name sampled at $res_name frequency";
    my $fmt = $conf->must_get_val(DIGESTRES=>$res, ATTR=>'PLOT_FMT');
    my $fmt_xlabel = join '/', map {code2unit($_)} split //, $fmt;

    $fmt = join ':', map {"%$_"} split //, $fmt;
    my $xrange = (defined $ARGV[2] && $ARGV[2] eq 'fake')? '' :
	    "set xrange [\"$xr_start\":\"$xr_end\"]\n";
    my $xtics = ($res == 30)? "set xtics 300\nset mxtics\n" : "";

    warn "xrange = $xrange" if DEBUG;

    print GNUPLOT <<"STOP";
set terminal png small color
set xdata time
set format x \"$fmt\"
set timefmt "%Y/%m/%d/%H/%M/%S"
$xrange
set nokey
set grid
$xtics
set xlabel "Time ($fmt_xlabel)"

set ylabel "Loss (%)"
set title \"$loss_title\"
set output "$loss_png"
plot [] [0:100] "$gnu_dat" using 1:5 ps $psize

set ylabel "Delay (ms)"
set title \"$delays_title\"
set output "$delays_png"
STOP

    print GNUPLOT "set multiplot\n" if ($got_inf_med || $got_inf_ninety);
    print GNUPLOT "plot '$gnu_dat' using 1:2:3:4 with errorbars ps $psize\n";

    if ($got_inf_med) {
	print GNUPLOT "plot '$gnu_inf_med' using 1:2 pt 3 ps 2\n";
    }

    if ($got_inf_ninety) {
	print GNUPLOT "plot $gnu_inf_ninety using 1:2 pt 4 ps 2\n";
    }
    print GNUPLOT "set nomultiplot\n" if ($got_inf_med || $got_inf_ninety);

    if ($archive_png) {
	my $archived_delays_file = "$archived_prefix.delay.png";
	unless (-e $archived_delays_file) {
	    link $delays_png, $archived_delays_file
		    or die "link $delays_png, $archived_delays_file: $!";
	}
	
	warn "archived $archived_delays_file";

	my $archived_loss_file = "$archived_prefix.loss.png";
	unless (-e $archived_loss_file) {
	    link $loss_png, $archived_loss_file
		    or die "link $loss_png, $archived_loss_file: $!";
	}

	warn "archived $archived_loss_file";
    }

    close GNUDAT; # releases the lock for this resolution
    warn "plotted files: $delays_png $loss_png" if VERBOSE;
    warn "data file: $gnu_dat" if VERBOSE;
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

# Given a number <alpha> in [0, 1], compute
# min {x: F(x) >= alpha}#
# where F is the empirical distribution function (in our case,
# with a fuzz factor due to use of buckets. Multiply the result
# by 1000 to convert from sec to ms.
sub get_percentile {
    my ($alpha, $sent, $pairs_ref, $lost) = @_;
    my $sum = 0;

     unless ((0.0 <= $alpha) && ($alpha <= 1.0)) {
 	warn "get_percentile: alpha must be between 0 and 1";
 	return undef;
     }

    return 'inf' if ($alpha + ($lost/$sent) > 1.0);
    
    for my $pair (@{$pairs_ref}) {
	my ($index, $count) = @{$pair};
	$sum += $count;

	return index2pt($index)*THOUSAND if $sum >= $alpha*$sent;
    }

    return CUTOFF_D*THOUSAND;
}

# return start time in seconds if the file is younger than a given 
# number of seconds, and undef otherwise.
sub is_younger_than {
    my ($filename, $age, $init) = @_;

    my ($start, $end) = split /_/, $filename;
    my $bigstart = Math::BigInt->new($start);
    my ($sec, $frac_sec) = $bigstart->brsft(32);

    $sec =~ s/^\+//;

    my $sec70 = OWP::Utils::time2time_1970($sec);

    return $sec if (defined $ARGV[2] && $ARGV[2] eq 'fake');

    return ($init - $sec70 < $age)? $sec : undef;
}

sub printlist {
    my $mesg = join " ", @_;
    warn $mesg;
}

sub code2unit {
    my $t = $_[0];
    $t eq 'H' && return 'hour';
    $t eq 'M' && return 'minute';
    $t eq 'S' && return 'second';
    $t eq 'd' && return 'day';
    $t eq 'm' && return 'month';
    $t eq 'y' && return 'year'
};

sub ymdHMS {
    my ($second, $minute, $hour, $day, $mon, $year, $wday, $yday)
	    = gmtime($_[0]);
    $mon++;
    $year += 1900;

    return ($year, $mon, $day, $hour, $minute, $second);
}

sub get_buck_ref {
    my ($fh, $fname) = @_;

    my ($header, $prec, $sent, $lost, $dup, $buf, $min, $pre);

    $pre = MAGIC_SIZE + VERSION_SIZE + HDRSIZE_SIZE;

    die "Cannot read header: $!" if (read($fh, $buf, $pre) != $pre);
    my ($magic, $version, $hdr_len) = unpack "a8xCC", $buf;

    my $remain_bytes = $hdr_len - $pre;

    die "Currently only work with version 1: $fname" unless ($version == 1);
    die "Cannot read header"
	    if (read($fh, $buf, $remain_bytes) != $remain_bytes);
    ($prec, $sent, $lost, $dup, $min) = unpack "CLLLl", $buf;
    $min /= THOUSAND; # convert from usec to ms
    if (VERBOSE) {
	printlist("magic = $magic", "version = $version",
		  "hdr_len = $hdr_len", "prec = $prec", "sent = $sent",
		  "lost = $lost", "dup = $dup", "min = $min");
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
	warn "num_rec = $num_records\n" if DEBUG;
    }

    for (my $i = 0; $i < $num_records; $i++) {
	my $buf;
	read $fh, $buf, 8 or die "Could not read: $!";
	my ($index, $count) = unpack "LL", $buf;
	next unless $count;
	push @pairs, [$index, $count];
    }

    # Lost packets get "infinite" delay.
#    push @pairs, [MAX_BUCKET, $lost] if $lost;

    return [$sent, $min, $lost, \@pairs, $prec];
}

sub print_pairs {
    my @pairs = @{$_[0]};
    for my $pair (@pairs) {
	print join " ", @{$pair}, "\n";
    }
}

sub fmt {
    return sprintf "%.2f", $_[0];
}
