#!/usr/local/bin/perl -w

# File: nodemaster.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script sends time updates to a designated port on the central
# host and manages a persistent piece of data describing a fixed
# number of the last reboots.

# Read configuration section to fine-tune scripts behaviour.

# Usage: livenotify.pl

use strict;
use constant JAN_1970 => 0x83aa7e80; # offset in seconds
use constant TMP_SECRET => 'abcdefgh12345678';
use Math::BigInt;
use IO::Socket;
use FindBin;
use lib ("$FindBin::Bin");
use OWP;
use Digest::MD5;
use GDBM_File;

### Start of the configuration section. Change these values as appropriate.
use constant VERBOSE => 2;
use constant DEBUG => 1;  # XXX - eventually set to 0 for production
use constant NUM_INTERVALS => 10; # max number of intervals in liveness updates

# ASCII address of the local node - to be used as directory
# on the central host
die "Usage:$FindBin::Script addr confdir" if($#ARGV != 2);
my $local_addr = $ARGV[0];
my $conf = new OWP::Conf($local_addr, $ARGV[1]);

# my $remote_host = 'marsalis.internet2.edu';
my $remote_host = $conf->{'UPTIMESENDTOADDR'};

my $port = $conf->{'UPTIMESENDTOPORT'};

# this local dir contains the subtree of senders to the local host
my $local_top = $conf->{'NODEDATADIR'};

# remote dir to place the files. NOTE: make sure it exists!
# my $remote_top = 'owp/owamp/scripts';	
my $remote_top = $conf->{'CENTRALUPLOADDIR'};

# this directory contains owampd configuration files describes below.
my $owampd_confdir = $conf->{'OWAMPDVARPATH'};

# These files are relative to $owampd_confdir::
my $owampd_pid_file = 'owampd.pid';    # file containing owampd pid
my $owampd_info_file = 'owampd.info';  # file containing starttime

# separator of items in update messages
my $update_sep = '_';

# this file keeps the last NUM_INTERVALS live time intervals
my $log_file = "$top_dir/liveness.dat";

### End of configuration section.

chdir $local_top or die "could not chdir $local_top: $!";


unless (defined($conf->{'SECRETNAME'}) &&
				defined($conf->{$conf->{'SECRETNAME'}})){
    warn "no secret found in $conf->{'GLOBALCONF'} - using a fake one";
    $secret = TMP_SECRET;
}
$secret = $conf->{$conf->{'SECRETNAME'}};

# Read owampd start time.
my $info_path = "$owampd_confdir/$owampd_info_file";
open INFO, "<$info_path" or die "Could not open $info_path: $!";
my $starttime = <INFO>;
die "Could not find start time in $info_path" unless $starttime;
chomp $starttime;
close INFO;

# Read owampd pid.
my $pid_path = "$owampd_confdir/$owampd_pid_file";
open PID_FILE, "<$pid_path" or die
	"could not open $pid_path: $!";
my $pid = <PID_FILE>;
close PID_FILE;
die "Could not find pid in $pid_path" unless $pid;
chomp $pid;

my $offset_1970 = new Math::BigInt JAN_1970;
my $scale = new Math::BigInt 2**32;

# Open the database and read in its contents. Currently only one key.
tie my %state, 'GDBM_File', $log_file, &GDBM_WRCREAT, 0640;
my $start = time;
if (defined $state{'live_times'}) {

    # these are just unscaled return values from `time'
    my @intervals = split /$update_sep/, $state{'live_times'};

    # If reached the limit then just shift off one pair. This way code
    # in the main loop only needs to change the last interval.
    if (@intervals == 2*NUM_INTERVALS) {
	shift @intervals;
	shift @intervals;
    }
    push @intervals, $start, time();
    $state{'live_times'} = join($update_sep, @intervals);
} else {
    $state{'live_times'} = join($update_sep, $start, time());
}

socket(my $socket, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
	or die "socket: $!";
my $remote_addr = sockaddr_in($port, inet_aton($remote_host));
connect $socket, $remote_addr 
	or die "Could not connect to $remote_host:$port : $!";

print "transferring to $remote_user:$remote_top\n" if VERBOSE;
# die "DEBUG set - exiting" if DEBUG;

while (1) {

    if (kill(0, $pid) != 1) {
	warn "could not signal pid $pid: $!";
	die "DEBUG set - exiting" if DEBUG;
	next;
    }
    print "owampd process $pid alive...\n" if VERBOSE;

    # Update the database.
    my $curtime = time;
    my @intervals = split /$update_sep/, $state{'live_times'};
    $intervals[$#intervals] = $curtime;
    $state{'live_times'} = join($update_sep, @intervals);

    my @owp_intervals = map(time2owptime, @intervals);

    # Hash the message with the secret key and send it
    my $msg = join($sep, $local_node, @owp_intervals);
    my $plain = join($sep, $msg, $secret);
    my $hashed = Digest::MD5::md5_hex($plain);
    my $msg_for_send = join($sep, $hashed, $msg);
    warn "sending ", $msg_for_send, "\n\n" if VERBOSE;
    send $socket, $msg_for_send, 0;
}

# Convert value return by time() into owamp-style (ASCII form
# of the unsigned 64-bit integer [32.32]
sub time2owptime {
    my $bigtime = new Math::BigInt $_[0];
    $bigtime = ($bigtime + $offset_1970) * $scale;
    $bigtime =~ s/^\+//;
    return bigtime;
}
