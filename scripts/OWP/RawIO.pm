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
#	File:		RawIO.pm
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Thu Oct 10 10:20:00 MDT 2002
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
package OWP::RawIO;
require 5.005;
require Exporter;
use strict;
use POSIX;
use FindBin;
use Errno qw(EINTR);

@ISA = qw(Exporter);
@EXPORT = qw(sys_readline);

$RawIO::REVISION = '$Id$';
$RawIO::VERSION='1.0';

sub sys_readline{
	my($fh) = @_;
	my $char;
	my $read;
	my $fname = "";

	while(1){
		$read = sysread($fh,$char,1);
		if(!defined($read)){
			next if($! == EINTR);
			die "sysread: $!";
		}
		next if($read < 1);
		return $fname if($char eq "\n");
		$fname .= $char;
	}
}

sub sys_writen{
	my($fh,$buf) = @_;
	my($len,$offset,$written);

	$len = length($buf);
	$offset = 0;

	while($len){
		my $written = syswrite $fh, $buf, $len, $offset;
		if(!defined($written)){
			next if($! == EINTR);
			die "syswrite: $!";
		}
		$len -= $written;
		$offset += $written;
	}

	1;
}

1;
