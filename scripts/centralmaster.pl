#!/usr/bin/perl -w

# File: centralmaster.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script runs on the central host. It validates the data
# as it comes, and runs owdigest on it.

use strict;
use Socket;
use Sys::Hostname;
use Fcntl;
use Digest::MD5;

use constant DEBUG => 1;
use constant TMP_SECRET => 'abcdefgh12345678';

### Configuration section.
my $server_port = 2345;

# $top_dir contains the hierarchy of receiver directories
my $top_dir = '/home/karp/owp/owamp/scripts';

# path to the 'owdigest' executable.
my $digest_path = '/home/karp/owp/owamp/owdigest/owdigest';

# this is the file containing the secret to hash timestamps with.
my $passwd_file = '/home/karp/owp/owamp/etc/owampd.passwd';

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

socket(my $server, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
my $iaddr = gethostbyname(hostname());
my $proto = getprotobyname('udp');
my $paddr = sockaddr_in($server_port, $iaddr);

# Initialize data structures for keeping track of updates.
my %live_times;   # this hash keeps track of intervals [start_time, cur_time]
                  # ordered by start_time in the increasing order

socket($server, PF_INET, SOCK_DGRAM, $proto)   || die "socket: $!";
bind($server, $paddr)                          || die "bind: $!";

# The server will only attempt to digest files if it keeps
# getting current time updates from hosts. Even as data keeps
# coming in through ssh nothing can be done with until it's
# validated - which is only done via timestamps. 

my $buf;
while (1) {
  if (my $srcaddr = recv($server, $buf, 128, 0)) {
    next unless $buf;
    my ($port, $addr) = sockaddr_in($srcaddr);
    my $src = inet_ntoa($addr);
    my ($start_time, $cur_time, $hashed) = split /\./, $buf;
    my $plain = "$start_time.$cur_time.$secret";
    unless (Digest::MD5::md5_hex("$start_time.$cur_time.$secret") eq $hashed) {
      warn "DEBUG: hash mismatch\n";
      warn "\$plain = $plain\n";
      next;
    }

    # Update the list of live intervals, or initialize it if there's none.
    if (exists $live_times{$src}) {
      my $last_index = $#{$live_times{$src}};
      if ($start_time > $live_times{$src}[$last_index][0]) {
	print "DEBUG: received new start time: $start_time\n" if DEBUG;
	push @{$live_times{$src}}, [$start_time, $cur_time];
      }

      for (my $i = $last_index; $i >= 0; $i--) {
	if (DEBUG) {
	  warn "DEBUG: start time = $start_time\n";
	  warn "DEBUG: time[$i][0] = @{[ $live_times{$src}[$i][0] ]}\n";
	  warn "DEBUG: time[$i][1] = @{[ $live_times{$src}[$i][1] ]}\n";
	}
	if ($start_time == $live_times{$src}[$i][0]) {
	  print "DEBUG: matched $start_time\n" if DEBUG;
	  if ($cur_time > $live_times{$src}[$i][1]) { # grow the interval
	    if (DEBUG) {
	      warn "DEBUG: growing the upper boundary...\n";
	      print "\t", "$live_times{$src}[$i][1] ---> $cur_time\n";
	    }
	    $live_times{$src}[$i][1] = $cur_time;
	  }
	}
      }
    } else {
      @{$live_times{$src}} = ();
      push @{$live_times{$src}}, [$start_time, $cur_time];
    }

    # When get a new update for a host - process all files for which
    # it a sender. Then can return back into the loop - since there's
    # no more information to act upon
    my @dirlist = qw(recv_a);
    for my $dir (@dirlist) {
      chdir "$top_dir/$dir/$src" or die "Could not chdir $dir/$src: $!";
      my $out =  qx/ls/;
      warn "\nDEBUG: printing contents of $dir/$src:\n$out\n" if DEBUG;
      my @files = split /\s/, $out;
      for (@files) {
	my $name = $_;
	next unless ($name =~ s/\.owp$//);
	my ($start, $end) = split /_/, $name;
	print "start=$start    end=$end\n";

	# XXX - do validation here...
	warn "running $digest_path $_";
	system("$digest_path $_ $_.digest > /dev/null");
	warn "archiving $_";
	archive($_);
      }
    }
    warn "DEBUG: no more dirs - going back into the recv loop\n\n" if DEBUG;
    sleep 5;
  }
}

# Archiving function - currently unlink.
sub archive {
  my $file = $_[0];
  unlink $file or warn "Could not unlink $file: $!";
}
