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
# use constant JAN_1970 => 0x83aa7e80; # offset in seconds
use constant TMP_SECRET => 'abcdefgh12345678';
use Math::BigInt;
use IO::Socket;
use FindBin;
use lib ("$FindBin::Bin");
use OWP;
use Digest::MD5;
use GDBM_File;

use constant VERBOSE => 2;
use constant DEBUG => 0;  # XXX - eventually set to 0 for production
use constant NUM_INTERVALS => 10; # max number of intervals in liveness updates

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");

# this directory contains owampd configuration files describes below.
my $owampd_confdir = $conf->{'OWAMPDVARPATH'};
my $remote_host = $conf->{'UPTIMESENDTOADDR'};
my $port = $conf->{'UPTIMESENDTOPORT'};
my $local_node = $conf->get_val(ATTR => 'NODE');

# These files are relative to $owampd_confdir::
my $owampd_pid_file = $conf->{'OWAMPDPIDFILE'};   # file containing owampd pid
my $owampd_info_file = $conf->{'OWAMPDINFOFILE'}; # file containing starttime

# this file keeps the last NUM_INTERVALS live time intervals
my $log_file = $conf->{'UPTIME_DB'};
my $var_path = $conf->{'OWAMPDVARPATH'};

my $secret = $conf->{'SECRETNAME'};

# separator of items in update messages
my $update_sep = $conf->must_get_val(ATTR => 'SEPARATOR');

chdir $conf->{'DATADIR'} or die "could not chdir $conf->{'DATADIR'} $!";

# Open the database and read in its contents. Currently only one key.
tie my %state, 'GDBM_File', "$var_path/$log_file", &GDBM_WRCREAT, 0640;

# my $start = time;
my @live_int = ();
if (defined $state{'live_times'}) {

    # these are in owp format.
    @live_int = split /$update_sep/, $state{'live_times'};

    # If reached the limit then just shift off one pair. This way code
    # in the main loop only needs to change the last interval.
    if (@live_int == 2*NUM_INTERVALS) {
	shift @live_int;
	shift @live_int;
    }
}

# Update the list of live times.
my ($starttime, $pid) = get_owp_info("$owampd_confdir/$owampd_info_file",
				     "$owampd_confdir/$owampd_pid_file");
if (@live_int == 0 || $live_int[-2] ne $starttime) {
    push @live_int, $starttime, OWP::Utils::time2owptime(time);
    $state{'live_times'} = join($update_sep, @live_int);
}

socket(my $socket, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
	or die "socket: $!";
my $remote_addr = sockaddr_in($port, inet_aton($remote_host));
connect $socket, $remote_addr 
	or die "Could not connect to $remote_host:$port : $!";

# XXX - May need to make this configurable.
my $sleeptime = 5;

while (1) {

    if (kill(0, $pid) != 1) {
	warn "could not signal pid $pid: $!";
	die "DEBUG set - exiting" if 0;

	sleep $sleeptime;
	($starttime, $pid) = get_owp_info("$owampd_confdir/$owampd_info_file",
					  "$owampd_confdir/$owampd_pid_file");
	next;
     }
    # Update the database.
    my @intervals = split /$update_sep/, $state{'live_times'};

    my $curtime = OWP::Utils::time2owptime(time);
    $intervals[$#intervals] = $curtime;

    print "intervals: ", join " ", @intervals, "\n" if DEBUG;

    $state{'live_times'} = join($update_sep, @intervals);

    # Hash the message with the secret key and send it
    my $msg = join($update_sep, $local_node, @intervals);
    my $plain = join($update_sep, $msg, $secret);
    my $hashed = Digest::MD5::md5_hex($plain);
    my $msg_for_send = join($update_sep, $hashed, $msg);
    warn "sending ", $msg_for_send, "\n\n" if VERBOSE;
    send $socket, $msg_for_send, 0;

    sleep $sleeptime;
}


# Fetch owampd starttime and pid.
sub get_owp_info {
    my ($infofile, $pidfile) = @_;
    my ($starttime, $pid);

    # Read owampd start time.
    open INFO, "<$infofile" or die "Could not open $infofile: $!";
    $starttime = <INFO>;
    die "Could not find start time in $infofile" unless $starttime;
    close INFO;
    chomp $starttime;

    # Read owampd pid.
    open PID_FILE, "<$pidfile" or die
	    "could not open $pidfile: $!";
    $pid = <PID_FILE>;
    die "Could not find pid in $pidfile" unless $pid;
    close PID_FILE;
    chomp $pid;

    return ($starttime, $pid)
}
