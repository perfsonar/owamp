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
use vars qw(@ISA @EXPORT $VERSION);
use POSIX;
use FindBin;
#use Errno qw(EINTR EIO :POSIX);

@ISA = qw(Exporter);
@EXPORT = qw(sys_readline sys_writeline);

$RawIO::REVISION = '$Id$';
$VERSION = $RawIO::VERSION='1.0';

sub sys_readline{
	my(%args) = @_;
	my($fh,$tmout) = (\*STDIN,0);
	my($cb) = sub{return undef};
	my $char;
	my $read;
	my $line = "";
	$tmout = $args{'TIMEOUT'} if(defined $args{'TIMEOUT'});
	$fh = $args{'FILEHANDLE'} if(defined $args{'FILEHANDLE'});
	$cb = $args{'CALLBACK'} if(defined $args{'CALLBACK'});

	while(1){
		eval{
			local $SIG{ALRM} = sub{die "alarm\n"};
			alarm $tmout;
			$read = sysread($fh,$char,1);
			alarm 0;
		};
		return &$cb(undef) if(!defined($read));
		if($read < 1){
			return &$cb($read)
		}
		if($char eq "\n"){
#warn "RECV: $line\n";
			return $line;
		}
		$line .= $char;
	}
}

sub sys_writeline{
	my(%args) = @_;
	my($fh,$line,$md5,$tmout) = (\*STDOUT,'',undef,0);
	my($cb) = sub{return undef};
	$line = $args{'LINE'} if(defined $args{'LINE'});
	$tmout = $args{'TIMEOUT'} if(defined $args{'TIMEOUT'});
	$fh = $args{'FILEHANDLE'} if(defined $args{'FILEHANDLE'});
	$cb = $args{'CALLBACK'} if(defined $args{'CALLBACK'});
	$md5 = $args{'MD5'} if(defined $args{'MD5'});

	$md5->add($line) if((defined $md5) && !($line =~ /^$/));

	$line .= "\n";
	my $len = length($line);
	my $offset = 0;

	while($len){
		my $written;
		eval{
			local $SIG{ALRM} = sub{die "alarm\n"};
			alarm $tmout;
			$written = syswrite $fh,$line,$len,$offset;
			alarm 0;
		};
		return &$cb(undef) if($@ && ($@ eq "alarm\n"));
		if(!defined($written)){
			next if($! == EINTR);
			return &$cb(undef);
		}
		$len -= $written;
		$offset += $written;
	}

#warn "TXMT: $line";
	return 1;
}
1;
