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

use constant DEBUG => 1;

### Configuration section.
my $server_port = 2345;
my $top_dir = '/home/karp/owp/owamp/scripts';
my $digest_path = '/home/karp/owp/owamp/owdigest/owdigest';

### End of configuration section.

chdir $top_dir or die "Could not chdir to $top_dir: $!";

socket(my $server, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
my $iaddr = gethostbyname(hostname());
my $proto = getprotobyname('udp');
my $paddr = sockaddr_in($server_port, $iaddr);

# Initialize data structures for keeping track of updates.
my %starts;        # this hash maps host to its start times
my %lower;         # this hash maps host to its list of last current
                   # reports before a new start

my %last_cur;      # this has maps each host to its last current report

my $last_cur = 0;

socket($server, PF_INET, SOCK_DGRAM, $proto)   || die "socket: $!";
bind($server, $paddr)                          || die "bind: $!";

# The server will only attempt to digest files if it keeps
# getting current time updates from hosts. Even as data keeps
# coming in through ssh nothing can be done with until it's
# validated - which is only done via timestamps. 

while (1) {
  if (my $srcaddr = recv($server, my $msg, 128, 0)) {
  
    my ($port, $addr) = sockaddr_in($srcaddr);  # Child
    my $src = inet_ntoa($addr);
    
    next unless $msg;
    chomp $msg;
    my ($type, $time) = split /=/, $msg;
    unless (exists $last_cur{$src}){
      $last_cur{$src} = 0;
    }
  
    if ($type eq 'start') {
      unless (exists $starts{$src}) {
	$starts{$src} = [];
	$lower{$src} = [];
      }
      
      # Do something to prevent the case where $last_cur is bigger than $time
      push @{$starts{$src}}, $time;
      push @{$lower{$src}}, $last_cur;
      
    } elsif ($type eq 'cur_time') {
      $last_cur{$src} = ($time > $last_cur{$src})? $time : $last_cur{$src};
    }
    
    warn "DEBUG: type=$type time=$time from $src\n" if DEBUG;

    # When get a new update for a host - process all files for which
    # it a sender. Then can return back into the loop - since there's
    # no more information to act upon
    my @dirlist = qw(recv_a);
    for my $dir (@dirlist) {
      chdir "$top_dir/$dir/$src" or die "Could not chdir $dir/$src: $!";
      my $out =  qx/ls/;
      warn "DEBUG: printing contents of $dir/$src:\n$out\n" if DEBUG;
      my @files = split /\s/, $out;
      for (@files) {
	my $name = $_;
	next unless ($name =~ s/\.owp$//);
	my ($start, $end) = split /_/, $name;
	print "start=$start    end=$end\n";

	# XXX - do validation here...
	system("$digest_path $_ $_.digest > /dev/null");
	archive($_);
      }
    }
    warn "DEBUG: no more dirs - going back into the recv loop\n" if DEBUG;
    sleep 5;
  }
}

# Archiving function - currently unlink.
sub archive {
  my $file = $_[0];
  unlink $file or warn "Could not unlink $file: $!";
}
