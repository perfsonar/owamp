#!/usr/local/bin/perl -lw

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

### Start of configuration section. Change these values as appropriate.

my $local_md5_path = '/sbin/md5';           # path to local md5 program
my $remote_md5_path = '/usr/bin/md5sum';    # same on the remote host
my $remote_user = 'karp\@sss.advanced.org'; # argument to scp
my $remote_top = 'datadir';                 # remote dir to place the files
                                            # NOTE: make sure it exists!

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

### End of configuration section.

my $dirname = $ARGV[0] || '.';                    # top local directory
chdir $dirname or die "could not chdir: $!";

# Forever look for new data.
while (1) {
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


