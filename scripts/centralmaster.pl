#!/usr/bin/perl -w

# File: centralmaster.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script runs on the central host. It validates the data
# as it comes, and runs owdigest on it.

use strict;
use IO::Socket::INET;

### Configuration section.
my $server_port = 2345;

my $server = IO::Socket::INET->new(LocalPort => $server_port,
				Type => SOCK_STREAM,
				Reuse => 1,
				Listen => 20)
	or die "Could not bind to port $server_port: $!\n";

REQUEST:
while (my $client = $server->accept()) {
  my $kidpid;
  if ($kidpid = fork) {
    close $client;
    next REQUEST;
  }

  defined($kidpid) or die "Coudl not fork: $!";
  close $server;

  select($client);
  while (1) {
    my $line = <$client>;
    next unless $line;
    print STDOUT $line;
  }
}
