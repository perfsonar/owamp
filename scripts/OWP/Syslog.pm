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
#	File:		Syslog.pm
#
#	Author:		Jeff W. Boote
#			Internet2
#
#	Date:		Wed Oct 09 12:52:45 MDT 2002
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
package OWP::Syslog;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

$VERSION = '1.00';

use Sys::Syslog;
use FindBin;


sub HandleDieWarn {
	my $this = shift;
	my @fh = @_;
	my $prio = $this->{'priority'};

	return if (1 == $this->{'isDIEWARN'});  ## already been here

	## trap these special cases so they go through the syslog fh.
	$this->{'warn_sub'} = $SIG{__WARN__};
	$this->{'die_sub'}  = $SIG{__DIE__};
	$SIG{__WARN__} = sub {
		print $_ @_ foreach(@fh);
		syslog $prio, "%s", join('',@_);
		return;
	};
	my $insig = 0;
	$SIG{__DIE__} = sub {  ## still dies upon return
		die @_ if $^S; ## see perldoc -f die perlfunc
		die @_ if $insig; ## protect against reentrance.
		$insig = 1;
		foreach(@fh){
			# the "real" die function prints to stderr,
			# so we want to skip this one if it is
			# in our list.
			next if($_->fileno == STDERR->fileno);
			print $_ @_;
		}
		syslog $prio, "%s", join('',@_);
		$insig = 0;
		return;
	};

	## mark that this object redefined warn/die handlers
	$this->{'isDIEWARN'} = 1;
}

my %defs = (
	facility	=>	'local0',
	priority	=>	'err',
	identity	=>	$FindBin::Script,
	log_opts	=>	'pid',
	setlogsock	=>	'inet',
	);

sub TIEHANDLE {
	my $this = {};

	my $class    = shift;
	my %args	= @_;
	$this->{$_} = $args{$_} || $defs{$_} foreach (keys %defs);
	$this->{'isDIEWARN'} = 0;

	## setup syslog setlogsock
	##
	## Many still have original Sys::Syslog which does not have
	## the setlogsock routine. There is no $VERSION constant to
	## test in Sys::Syslog, so we'll test the symbol table to see
	## if the routine exists. If not, skip this gracefully.
	if ( defined($Sys::Syslog::{'setlogsock'}) ) {
		my $sock = $this->{'setlogsock'};
		return undef unless ($sock =~ /^(unix|inet)$/);

		## boy this is messy... must be this way, or compile time error
		no strict 'refs';
		my $call = 'Sys::Syslog::setlogsock';
		&$call($sock);
		use strict 'refs';
	}

	$this->{'log_opts'}.=',nowait' if(!($this->{'log_opts'} =~ /nowait/));
	## open a syslog connection
	openlog $this->{'identity'},$this->{'log_opts'},$this->{'facility'};
	syslog "debug","Opened syslog";

	return bless $this, $class;
}

sub PRINT {
	my $this = shift;
	syslog $this->{'priority'}, "%s", join('',@_);
}

sub PRINTF {
	my $this = shift;
	syslog $this->{'priority'}, @_;
}

sub FILENO {
	my $this = shift;
	if ( exists($this->{fh}) ) {
		return fileno($this->{fh});
	}
	return undef;
}

sub EOF {
	my $this = shift;
	if ( exists($this->{fh}) ) {
		return eof($this->{fh});
	}
	return undef;
}

sub BINMODE {
	my $this = shift;
	if ( exists($this->{fh}) ) {
		return binmode($this->{fh});
	}
	return undef;
}

sub TELL {
	my $this = shift;
	if ( exists($this->{fh}) ) {
		return tell($this->{fh});
	}
	return undef;
}

sub DESTROY {
	my $this = shift;

	if ($this->{'isDIEWARN'}) {
		## restore signal handlers
		{ local $^W = 0; ## hey, why can't I undef $SIG{__DIE__} w/out warns?
		$SIG{__WARN__} = $this->{'warn_sub'};
		$SIG{__DIE__}  = $this->{'die_sub'};
		}
	}

	## close syslog
	closelog;

	## destroy mem object
	undef $this;
}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OWP::Syslog - Tie a filehandle to Syslog. If you Tie STDERR, then all STDERR errors are automatically caught, or you can debug by Carp'ing to STDERR, etc. (Good for CGI error logging.)

=head1 SYNOPSIS

  use OWP::Syslog;

  ###
  ##  Pass up to five args:
  ##    facility	=> 'local0',
  ##	priority	=> 'err',
  ##    identity	=> 'my_program'
  ##    log_opts	=> 'pid,cons'		# defaults to 'pid'
  ##    setlogsock	=> 'inet'|'unix'	# defaults to inet
  ###
  tie *MYLOG, 'Tie::Syslog', facility => 'local0', setlogsock => 'unix';
  
  print MYLOG "I made an error."; ## this will be syslogged
  printf MYLOG "Error %d", 42;    ## syslog as "Error 42"

  untie *MYLOG;

=head1 DESCRIPTION

This module allows you to tie a filehandle (output only) to syslog. This
becomes useful in general when you want to capture any activity that
happens on STDERR and see that it is syslogged for later perusal. You
can also create an arbitrary filehandle, say LOG, and send stuff to syslog
by printing to this filehandle. This module depends on the Sys::Syslog
module to actually get info to syslog.

Tie your filehandle to syslog using a glob to the filehandle. When it is
tied to the 'Tie::Syslog' class, you may optionally pass four arguments
that determine the behavior of the output bound to syslog.

The arguments are specified in any order using hash-array notation.

The 'facility' and 'priority' are used to direct your filehandle traffic
to the proper channels in syslog. I suggest reviewing a manpage for syslog
on your local system to identify what the facilities and priorities actually
are. (The defaults are set to 'local0' and 'err' respectively.

The 'identifier' string is the string that shows up in evey line of output
that syslog writes. You may use this identifier to help sort out syslog
lines produced by different applications (with different id's.) If you do
not specify a value for this argument, it will default to the name of the
running program. (This is derived from FindBin::Script.)

The 'log_opts' is a string of comma separated log options specific
to syslog. Current documentation supports 'pid,cons,ndelay,nowait'. Check
your local listings, as you may pass values that are only part of your
local system. I suggest checking your man pages for syslog, and perhaps
looking inside your site_perl/$archname/sys/syslog.ph for other such values.
If you do not pass this argument, it defaults to the string 'pid',
which makes syslog put a [12345] pid value on each line of output.

The 'setlogsock' argument is either the string 'inet' or 'unix'. This is
passed to the Sys::Syslog::setlogsock() call to specify the socket type
to be used when opening the connection to syslog. If this argument is
not specified, then the default used is 'inet'. Many perl installations
still have original Sys::Syslog which does not have the setlogsock()
routine. There is also no $VERSION constant to test in Sys::Syslog, so
we'll test the symbol table to see if the routine exists. If the routine
does not exist, then the fourth argument is silently ignored. I did not
want to require people to have "the latest" version of perl just to use
this module.


Note:  You can optionally pass a reference to a Filehandle as the *very*
first arg (before the 'Tie::Syslog' even...)  The *only* time you'd do
this is if you are experiencing trouble using your tied filehandle with
other code that expects to do calls like fileno() and binmode() to
operate on this tied filehandle. The TIEHANDLE api gives us no way (that
I have found) to get access to the actual tied variable, or filehandle in
this case. So, I have resorted to just passing it in as a arg right up front
and just storing it in the object. **THERE ARE PROBLEMS WITH THIS!!!** Be
aware, those of you this may affect...


An aside on catching die/warn messages:

HandleDieWarn

The blessed object that is returned from tie also has one additional
member function. In the case that you want to capture information
going to the warn() and die() functions. You may call HandleDieWarn()
to setup the proper handler function to deal with the special signals
__DIE__ and __WARN__. (The args to HandleDieWarn are a list of fh's to
optionally send the message to as well as syslog. If you send the "tied"
fh, you will see the message in syslog twice, so don't do that.)

  my $x = tie *MYLOG, 'OWP::Syslog', priority => 'debug';
  $x->HandleDieWarn(*STDERR);		## set __DIE__,__WARN__ handler
  					## can undef $x anytime after this...
					## arg is filehandle from "tie"

  print STDERR "I made an error.";	## this will be syslogged
  printf STDERR "Error %d", 42;		## syslog as "Error 42"
  warn "Another error was made.";	## this will also be syslogged
  eval {
      die "exception thrown";		## this is *NOT* syslogged
  };
  die "Killing me softly?!";		## syslogged, then script ends

  undef $x;				## be sure to do this, or warns!
  untie *STDERR;

=head1 AUTHOR

Copyright (c) 2002 UCAID (Jeff Boote). All rights reserved. This program has
been modified from the original version by Broc Seib. It is of course still
free software; and can be redistributed and/or modified under the same
terms as Perl itself. (GNU License)

Copyright (c) 1999-2002 Broc Seib. All rights reserved. This program is free
software; you can redistribute it and/or modify it under the same terms as
Perl itself.

=head1 REVISION

$Id$

=head1 SEE ALSO

Read perldoc perltie for info on how to tie a filehandle.
Read perldoc Sys::Syslog.
Read man syslog to learn more about syslog.
Read perldoc Tie::Syslog which this module was based upon.
Read perldoc FindBin which is used for the default 'ident'.

=cut
