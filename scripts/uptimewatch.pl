#!/usr/bin/perl -w

# File: uptimewatch.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script runs on the central host. It receives updates,
# removes discovered invalid data, and updates database of
# liveness intervals.

use strict;
use Socket;
use Sys::Hostname;
use Digest::MD5;
use GDBM_File;

use constant DEBUG => 1;
use constant VERBOSE => 1;

# max length of a udp message to wait for. being lazy here - need it large
# enough to cover md5, nodename, separators and NUM_INTERVALS many pairs 
# of ASCII-encoded timestamps.
use constant MAX_MSG => 1024;

### Configuration section.

use constant NUM_INTERVALS => 10; # max number of intervals in liveness updates
use constant TMP_SECRET => 'abcdefgh12345678';
use constant SERVER_PORT => 2345;

# separator of fields in update messages and database values
my $update_sep = '_';

# $top_dir contains the hierarchy of receiver directories
my $top_dir = '/home/karp/projects/owamp/datadep';

# path to the 'owdigest' executable.
my $digest_path = '/home/karp/projects/owamp/owdigest/owdigest';

# this is the file containing the secret to hash timestamps with.
my $passwd_file = '/home/karp/projects/owamp/etc/owampd.passwd';

# this is a log file with liveness reports from nodes
my $log_file = "$top_dir/liveness.dat";

# mesh types to watch for - will be set as: $conf->get_val(ATTR=>'MESHTYPES');
my @meshtypes = qw(v4 v6);

# XXX - see also sub definition of getattr at the end - remove it and
# replace its invocation with $conf->get_val !!!

### End of configuration section.

chdir $top_dir or die "Could not chdir to $top_dir: $!";

open(PASSWD, "<$passwd_file") or die "Could not open $passwd_file: $!";
my $secret = <PASSWD>;
unless ($secret) {
    warn "Could not read secret from $passwd_file";
    $secret = TMP_SECRET;
    die "Cannot function without a secret!" unless DEBUG;
}
chomp $secret;
close PASSWD;

# Open the database and read in its contents. The keys are nodenames.
tie my %live_db, 'GDBM_File', $log_file, &GDBM_WRCREAT, 0640;
for my $node (keys %live_db) {
    my @intervals = split /$update_sep/, $live_db{$_};
    update_node($top_dir, $node, @intervals)
}

socket(my $server, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
my $iaddr = gethostbyname(hostname());
my $proto = getprotobyname('udp');
my $paddr = sockaddr_in(SERVER_PORT, $iaddr);

socket($server, PF_INET, SOCK_DGRAM, $proto)   || die "socket: $!";
bind($server, $paddr)                          || die "bind: $!";

my $buf;

MESSAGE:
while (1) {
    if (my $srcaddr = recv($server, $buf, MAX_MSG, 0)) {

	# Parse the message and do sanity checks. Skip if invalid.
	unless ($buf) {
	    warn "empty message - skipping" if VERBOSE;
	    next;
	}
	my ($hashed, $plain) = split /$update_sep/, $buf, 2;
	unless ($plain) {
	    warn "empty plain message - skipping" if VERBOSE;
	    next;
	}
	warn "received $plain" if VERBOSE;
	unless (Digest::MD5::md5_hex($plain) eq $hashed) {
	    warn "DEBUG: hash mismatch\n";
	    warn "\$plain = $plain\n";
	    next;
	}
	my ($node, $intervals) = split /$update_sep/, $plain, 2;
	unless ($intervals) {
	    warn "empty list of intervals - skipping" if VERBOSE;
	    next;
	}
	my @intervals = split /$update_sep/, $intervals;
	unless ($#intervals % 2) { # last index must be odd
	    warn "odd number of elements in update - skipping" if VERBOSE;
	    next;
	}
	for my $i (1..$#intervals) {
	    unless ($intervals[$i-1] <= $intervals[$i] ) {
		warn "bad interval: $intervals[$i-1]:$intervals[$i] - skip";
		next MESSAGE;
	    }
	}

	# Update the list of live intervals, or initialize it if there's none.
	if ($live_db{$node}) {
	    my @saved = split /$update_sep/, $live_db{$node};
	    unless ($intervals[$#intervals] > $saved[$#saved]) {
		warn "out-dated message: skipping";
		next;
	    }
	}
	$live_db{$node} = $intervals;
	update_node($top_dir, $node, @intervals);
    }
}

# Return 1 if the interval [$low, $high] contains $point, and 0 otherwise.
sub contains {
    my ($low, $high, $point);
    return ($low <= $point && $point <= $high)? 1 : 0;
}

# given mesh type, and node name return ASCII address
# XXX - temporary plug - eventually to be replaced by
# $conf->get_val from Conf.pm module
sub getattr {
    return "127.0.0.1";
}

sub update_node {
    my ($top_dir, $node, @intervals) = @_;

    for my $type (@meshtypes) {

	# XXX - replace this with Conf::get_val
	my $sender = getattr(TYPE=>$type, NODE=>$node, ATTR=>'ADDR');

	my $mesh_subdir = "$top_dir/$type";
	opendir(DIR, "$mesh_subdir") 
		|| die "Cannot opendir $mesh_subdir: $!";
	my @receivers = grep {$_ !~ /^\./ && -d $_} readdir(DIR);
	closedir DIR;

	for my $recv (@receivers) {
	    my $dirpath = "$mesh_subdir/$recv/$sender";
	    next unless -d $dirpath;
	    opendir(OWPDATA, "$dirpath") 
		    or die "Could not opendir $dirpath: $!";
	    my @files = grep {-f $_} readdir(DIR);
	    closedir OWPDATA;
	    warn "$mesh_subdir\nrecv=$recv\nsrc=$sender\nfiles: @files \n"
		    if VERBOSE;

	  FILE:
	    for (@files) {
		my $filename = $_;
		next unless ($filename =~ s/\.owp$//);
		my ($start, $end) = split /_/, $filename;
		warn "start=$start    end=$end\n" if VERBOSE;
		my $fullpath = "$dirpath/$_";

		if ($end > $intervals[$#intervals]
		    || $start < $intervals[0]) {
		    warn "file $fullpath: status unknown: skipping\n"
			    if VERBOSE;
		    next;
		}

		for (my $i = 1; $i < $#intervals; $i++) {
		    if (contains($start, $end, $intervals[$i])) {
			warn "file $fullpath invalid: archiving\n"
				if VERBOSE;
			unlink $fullpath or 
				warn "Could not unlink $fullpath: $!";
			next FILE;
		    }
		}
	    }
	    warn "DEBUG: no more dirs - going back into recv loop\n\n"
		    if VERBOSE;
	    # sleep 5;
	}

    }
}
