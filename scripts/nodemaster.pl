#!/usr/local/bin/perl -w

# File: nodemaster.pl
# Author: Anatoly Karp, Internet2 2002
# $Id$

# This script manages uploading new data files to the central host
# (also referred to as remote host) and checks their integrity using
# md5 hash. It is assumed that <top_dirname>  contains one
# subdirectory for each node with which it is running tests.

# Read configuration section to fine-tune scripts behaviour.

# Usage: nodemaster.pl

use strict;
use constant JAN_1970 => 0x83aa7e80; # offset in seconds
use constant TMP_SECRET => 'abcdefgh12345678';
use Math::BigInt;
use IO::Socket;
use Digest::MD5;
use FindBin;
use lib ("$FindBin::Bin");
use OWP;

### Start of the configuration section. Change these values as appropriate.
use constant VERBOSE => 2;
use constant DEBUG => 1;  # XXX - eventually set to 0 for production

# ASCII address of the local node - to be used as directory
# on the central host
die "Usage:$FindBin::Script addr confdir" if($#ARGV != 2);
my $local_addr = $ARGV[0];
my $conf = new OWP::Conf($local_addr,$ARGV[1]);

# locations of md5 executables
# (The Conf module doesn't really help here... It only knows what "this"
# system should be using. perl -e "Digest::MD5->blah" is a much better
# solution.)
my $local_md5_path = $conf->{'MDCMD'};
my $remote_md5_path = '/usr/bin/md5sum';

# arguments to ssh and scp
#my $remote_user = 'karp\@marsalis.internet2.edu';
#my $remote_host = 'marsalis.internet2.edu';
my $remote_user = $conf->{'CENTRALHOSTUSER'}.'\@'.$conf->{'CENTRALHOST'};
my $remote_host = $conf->{'UPTIMESENDTOADDR'};
my $port = $conf->{'UPTIMESENDTOPORT'};

# this local dir contains the subtree of senders to the local host
my $local_top = $conf->{'NODEDATADIR'};

# remote dir to place the files. NOTE: make sure it exists!
# my $remote_top = 'owp/owamp/scripts';	
my $remote_top = $conf->{'CENTRALUPLOADDIR'};

my $data_suffix = '\.owp';	# suffix for data files (Perl)

# due to variety of md5 programs, the fields in which the md5 is found
# may vary. For example', FreeBSD's output of md5 program may look so:

# bash-2.05a$ md5 file
# MD5 (file) = ff68e78adcc3c8026174d95f4f9d1478

# while Debian's md5sum program yields:

# bash$ md5sum file
# ff68e78adcc3c8026174d95f4f9d1478  file

# the next two values give the field number (starting from 0)
# in which the md5 value for the corresponding host to be found:
my $local_md5_field = 0;
my $remote_md5_field = 0;

# this directory contains owampd configuration files describes below.
my $owampd_confdir = $conf->{'OWAMPDVARPATH'};

# These files are relative to $owampd_confdir::
my $owampd_pid_file = 'owampd.pid';    # file containing owampd pid
my $owampd_info_file = 'owampd.info';  # file containing starttime

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
open INFO, "<$info_path"
	or die "Could not open $info_path: $!";
my $start_time = <INFO>;
die "Could not find start time in $info_path"
	unless $start_time;
chomp $start_time;
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

socket(my $socket, PF_INET, SOCK_DGRAM, getprotobyname('udp'))
	or die "socket: $!";
my $remote_addr = sockaddr_in($port, inet_aton($remote_host));
connect $socket, $remote_addr 
	or die "Could not connect to $remote_host:$port : $!";

print "transferring to $remote_user:$remote_top\n" if VERBOSE;
# die "DEBUG set - exiting" if DEBUG;

while (1) {
    my $cur = new Math::BigInt time;
    $cur = ($cur + $offset_1970) * $scale;
    my $cur_time = "$cur";
    $cur_time =~ s/^\+//;

    if (kill(0, $pid) != 1) {
	warn "could not signal pid $pid: $!";
	die "DEBUG set - exiting" if DEBUG;
	next;
    }
    print "owampd process $pid alive...\n" if VERBOSE;

    # Hash the message with the secret key and send it
    my $msg = "$start_time.$cur_time";
    my $plain = "$msg.$secret";
    my $hashed = Digest::MD5::md5_hex($plain);
    warn "sending $msg.$hashed\n\n" if VERBOSE;
    send $socket, "$msg.$hashed", 0;

    # Look for new data.
    opendir(DIR, $addr) || die "can't opendir $local_top/$addr: $!";
    my @subdirs = grep {$_ !~ m#/\.# && -d $_} readdir(DIR);
    if (VERBOSE) {
	chomp(my $cwd = `pwd`);
	warn "cwd = $cwd - found subdirs: @subdirs\n\n" if VERBOSE;
    }
    closedir DIR;
    foreach my $subdir (@subdirs) {
	push_dir("$subdir");
    }
}

# this sub tries to push all files from the given directory to remote host.
# the argument is a path relative to $local_top
sub push_dir {
    my $dirlink = $_[0];
    my $rem_dir = "$remote_top/$dirlink";
    warn "push_dir: rem_dir = $rem_dir";
    my $cmd = "ssh $remote_user if test -f $rem_dir\\; " 
	    . "then rm -rf $rem_dir\\; fi\\; if test ! -d $rem_dir\\; "
		    . "then mkdir -p $rem_dir\\; fi";

    system($cmd);

    opendir DIR, $dirlink or die "Could not open $dirlink: $!";
    my @files = sort grep {$_ =~ /$data_suffix$/} readdir(DIR);
    closedir(DIR);

    unless (@files) {
	warn "no files found in $dirlink" if VERBOSE;
	die "DEBUG set - exiting" if DEBUG;
	next;
    }

    foreach my $file (@files) {
	my $local_file_path = "$local_top/$dirlink/$file";
	my $rem_file_path = "$rem_dir/$file";
	warn "DEBUG: rem_file_path = $rem_file_path" if DEBUG;
	push_try($local_file_path, $rem_file_path);
    }
}

# this sub attempts to transfer the file to the remote host 
# and deletes it on success
sub push_try {
    my ($local_file, $remote_file) = @_;
    warn "push_try: transferring $local_file to $remote_file" if VERBOSE;

    my $md5_string = qx/$local_md5_path $local_file/;
    chomp $md5_string;
    unless ($md5_string) {
	warn "no output from md5";
	return;
    }
    my @res = split(' ', $md5_string);
    chomp $res[$local_md5_field];
    unlink $local_file if 
	    push_ok($res[$local_md5_field],$local_file, $remote_file);
}

# try to scp a given file to the remote host and check its md5 value
# against the given one (presumably the one computed on localhost)
sub push_ok {
    my ($md5_loc, $local_path, $remote_path) = @_;

    my $rem_ipath = $remote_path . ".i";
    my $cmd = join(' ', 'scp', $local_path, "$remote_user:$rem_ipath",
		   '>/dev/null');

    if (VERBOSE) {
	warn "local md5 = $md5_loc";
	warn "cmd =  $cmd";
    }

    if (system($cmd) > 0) {
	warn "system($cmd) failed: $!";
	return undef;
    }

    my $out = qx!ssh $remote_user $remote_md5_path $rem_ipath!;
    return undef unless $out;
    my @res = split /\s/, $out;

    if ($md5_loc eq $res[$remote_md5_field]) {
	warn "successfully transferred: remote path = $remote_path\n\n"
		if VERBOSE;
	system("ssh $remote_user mv $rem_ipath $remote_path");
	return 1;
    } else {
	my $str = "md5 mismatch:\n local: $md5_loc\n remote: " .
		"$res[$remote_md5_field]\n";
	warn $str if VERBOSE;
	system("ssh $remote_user rm -rf $rem_ipath");
	return undef;
    }
}
