#!/usr/local/bin/perl -w

# File: nodemaster.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script manages uploading new data files to the central host
# (also referred to as remote host) and checks their integrity using
# md5 hash. It is assumed that <top_dirname>  contains one
# subdirectory for each node with which it is running tests.

# Read configuration section to fine-tune scripts behaviour.

# Usage: nodemaster.pl [top_dirname]

use strict;
use constant DEBUG => 1;
use constant JAN_1970 => 0x83aa7e80; # offset in seconds
use Math::BigInt;
use IO::Socket;

### Start of configuration section. Change these values as appropriate.

# NOTE: you have to run h2ph to be able to make use
# of syscall facility (fix path below if needed)
push @INC, '/usr/local/lib/perl5/site_perl/5.6.1/mach/sys';
require 'syscall.ph';

my $local_md5_path = '/sbin/md5';           # path to local md5 program
my $remote_md5_path = '/usr/bin/md5sum';    # same on the remote host
my $remote_user = 'karp\@sss.advanced.org'; # argument to scp
#my $remote_host = 'sss.advanced.org';
my $remote_host = 'mail.internet2.edu';
# my $remote_host = 'erdos.math.wisc.edu';
my $remote_top = 'datadir';                 # remote dir to place the files
                                            # NOTE: make sure it exists!

my $port = 2345;                            # port to sent updates to
my $data_suffix = '\.owp';                  # suffix for data files (Perl)

# due to variety of md5 programs, the fields in which the md5 is found
# may vary. For example', FreeBSD's output of md5 program may look so:
# bash-2.05a$ md5 file
# MD5 (file) = ff68e78adcc3c8026174d95f4f9d1478

# while Debian's md5sum program yields:
# bash$ md5sum file
# ff68e78adcc3c8026174d95f4f9d1478  file

# the next two values give the field number (starting from 0)
# in which the md5 value for the corresponding host to be found:
my $local_md5_field = 3;
my $remote_md5_field = 0;

my $interval = 3;                       # number of seconds between updates
my $owampd_pid_file = 'owampd.pid';     # file containing owampd pid

### End of configuration section.

my $dirname = $ARGV[0] || '.';                    # top local directory
chdir $dirname or die "could not chdir: $!";

my $offset_1970 = new Math::BigInt JAN_1970;
my $scale = new Math::BigInt 2**32;

# my $socket = IO::Socket::INET->new("$remote_host:$port")
#	or die "Could not connect to $remote_host:$port : $!";

socket(my $socket, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
	or die "socket: $!";
my $remote_addr = sockaddr_in($port, inet_aton($remote_host));
connect $socket, $remote_addr 
	or die "Could not connect to $remote_host:$port : $!";

# Set the timer to go off in 1 second, and every $interval seconds
# thereafter.  Call &sig_handler when it goes off.
$SIG{'ALRM'} = 'sig_handler';
my $value = pack('LLLL', $interval, 0, 1, 0);
syscall(&SYS_setitimer, 0, $value, 0);

my $got_alarm = 0;

while (1) {
  if ($got_alarm) {
    $got_alarm = 0;
    my $curtime = new Math::BigInt time;
    $curtime = ($curtime + $offset_1970) * $scale;
    my $str = "$curtime";
    $str =~ s/^\+//;
    unless (open(PID_FILE, $owampd_pid_file)) {
      warn "could not open $owampd_pid_file: $!";
      next;
    }
    my $pid = <PID_FILE>;
    close PID_FILE;
    chomp $pid;
    if (kill 0, $pid != 1) {
      warn "could not signal pid $pid: $!";
      next;
    }

    # Just for testing: randomly send start/cur_time messages..
    my $type = (rand() < 0.5)? 'start' : 'cur_time';
    warn "DEBUG: process pid $pid alive, sending $str\n";
    send $socket, "$type=$str\n", 0;
  }

  next if DEBUG;  # XXX - Eventually remove.

# Look for new data.
  opendir(DIR, '.') || die "can't opendir $dirname: $!";
  my @subdirs = grep {$_ !~ /^\./ && -d $_} readdir(DIR);
  print "found subdirs: @subdirs" if DEBUG;
  closedir DIR;
  foreach my $subdir (@subdirs) {
    push_dir($subdir);
  }
}

# this sub tries to push all files from the given directory to remote host.
# the argument is a path relative to $dirname
sub push_dir {
  my $subdir = $_[0];
  my $rem_path = "$remote_top/$subdir";
  my $cmd = "ssh $remote_user if test -f $rem_path\\; then rm -rf $rem_path\\; fi\\; if test ! -d $rem_path\\; then mkdir $rem_path\\; fi";
  system($cmd);

  opendir DIR, $subdir or die "Could not open $subdir: $!";
  my @files = grep {$_ !~ /^\./ && $_ =~ /^.*$data_suffix$/} readdir(DIR);
  closedir(DIR);

  unless (@files) {
    warn "no files in $subdir" if DEBUG;
    die "DEBUG: exiting..." if DEBUG; # XXX - comment out eventually
  }

  foreach my $file (@files) {
    push_try($subdir, $file);
  }
}

# this sub attempts to transfer the file to the remote host 
# and deletes it on success
sub push_try {
  my ($subdir, $file) = @_; # dirname and filename, respectively
  warn "push_try: transferring $subdir/$file" if DEBUG;
  my $path = "$subdir/$file";

  my $md5_string = qx/$local_md5_path $path/;
  chomp $md5_string;
  unless ($md5_string) {
    warn "no output from md5";
    return;
  }
  my @res = split(' ', $md5_string);
  chomp $res[$local_md5_field];
  unlink $path if push_ok($res[$local_md5_field], $remote_top, $subdir, $file);
}

# try to scp a given file to the remote host and check its md5 value
# against the given one (presumably the one computed on localhost)
sub push_ok {
  my ($md5_loc, $rem_top, $subdir, $filename) = @_;
  my $file_path = "$subdir/$filename";
  my $dirpath = ($rem_top)? "$rem_top/$subdir" : "$subdir";
  my $rem_cpath = "$dirpath/$filename";
  my $rem_ipath = $rem_cpath . ".i";
  my $cmd = join(' ', 'scp', $file_path, "$remote_user:$rem_ipath",
		 '>/dev/null');
#  print "DEBUG: local md5 = $md5_loc" if DEBUG;
#  print "DEBUG: cmd = ", $cmd if DEBUG;
  if (system($cmd) > 0) {
    warn "system($cmd) failed: $!";
    return undef;
  }

#  print "DEBUG: remote relative filename = $dirpath/$filename" if DEBUG;

  my $out = qx!ssh $remote_user $remote_md5_path $rem_ipath!;
  return undef unless $out;
  my @res = split /\s/, $out;

#  print "DEBUG: remote md5 = $res[$remote_md5_field]" if DEBUG;
  print "" if DEBUG;

  if ($md5_loc eq $res[$remote_md5_field]) {
    system("ssh $remote_user mv $rem_ipath $rem_cpath");
    return 1;
  } else {
    system("ssh $remote_user rm -rf $rem_ipath");
    return undef;
  }
}

sub sig_handler {
  $got_alarm = 1;
}
