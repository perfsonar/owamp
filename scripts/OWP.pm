#
#      $Id$
#
#########################################################################
#									#
#			   Copyright (C)  2002				#
#	     			Internet2				#
#			   All Rights Reserved				#
#									#
#########################################################################
#
#	File:		OWP.pm
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Tue Sep 24 11:23:49  2002
#
#	Description:	
#
#	Usage:
#
#	Environment:
#
#	Files:
#
#	Options:
package OWP;
require 5.005;
require Exporter;
use strict;
use FindBin;
use POSIX;
use Fcntl qw(:flock);
use FileHandle;
use vars qw(@ISA @EXPORT $VERSION);
use OWP::Conf;
use OWP::Utils;

@ISA = qw(Exporter);
@EXPORT = qw(daemonize);

$OWP::REVISION = '$Id$';
$VERSION = '1.0';

sub daemonize{
	my(%args)	= @_;
	my($dnull,$umask) = ('/dev/null','022');
	my $fh;

	$dnull = $args{'DEVNULL'} if(defined $args{'DEVNULL'});
	$umask = $args{'UMASK'} if(defined $args{'UMASK'});

	if(defined $args{'PIDFILE'}){
		$fh = new FileHandle $args{'PIDFILE'}, O_CREAT|O_RDWR;
		unless($fh && flock($fh,LOCK_EX|LOCK_NB)){
			die "Unable to lock pid file $args{'PIDFILE'}: $!";
		}
		my $pid = <$fh>;
		if(defined $pid){
			chomp $pid;
			die "$FindBin::Script:$pid still running..." if(kill(0,$pid));
		}
	}

	open STDIN, "$dnull"	or die "Can't read $dnull: $!";
	open STDOUT, ">>$dnull"	or die "Can't write $dnull: $!";
	if(!$args{'KEEPSTDERR'}){
		open STDERR, ">>$dnull"	or die "Can't write $dnull: $!";
	}

	defined(my $pid = fork)	or die "Can't fork: $!";

	# parent
	exit if $pid;

	# child
	$fh->seek(0,0);
	$fh->print($$);
	undef $fh;
	setsid			or die "Can't start new session: $!";
	umask $umask;

	return 1;
}

1;
