#!/usr/bin/perl -w
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
#	File:		collector.pl
#
#	Author:		Jeff W. Boote
#			Internet2
#
#	Date:		Tue Oct 08 11:15:49 MDT 2002
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
use strict;
use FindBin;
use lib ("$FindBin::Bin");
use Getopt::Std;
use Socket;
use POSIX;
use File::Path;
use Digest::MD5;
# use Errno qw(EINTR);
use OWP;
use OWP::Syslog;
use OWP::RawIO;
use Sys::Syslog;

my @SAVEARGV = @ARGV;

my %options = (
	CONFDIR	=>	"c:",
	);
my %optnames = (
	c	=> "CONFDIR",
	);
my %defaults = (
	CONFDIR	=> "$FindBin::Bin",
	);

my $options = join '', values %options;
my %setopts;
getopts($options,\%setopts);
foreach (keys %optnames){
	$defaults{$optnames{$_}} = $setopts{$_} if(defined($setopts{$_}));
}

# Fetch configuration options.
my $conf = new OWP::Conf(%defaults);

local(*MYLOG);
# setup syslog
my $slog = tie *MYLOG, 'OWP::Syslog',
		facility	=> $conf->must_get_val(ATTR=>'SyslogFacility'),
		log_opts	=> 'pid',
		setlogsock	=> 'unix';
# make die/warn goto syslog, and also to STDERR.
$slog->HandleDieWarn(*STDERR);
undef $slog;	# Don't need the ref anymore, and untie won't work if
		# I keep the ref.

#
# Initialize Mesh info
#
my($mtype,$recv,$send,$raddr,$saddr);
my @mtypes = $conf->must_get_val(ATTR=>'MESHTYPES');
my @nodes = $conf->must_get_val(ATTR=>'MESHNODES');

#
# data path information
#
my $datadir = $conf->must_get_val(ATTR=>'CentralDataDir');

#
# deamon values
#
my $port = $conf->must_get_val(ATTR=>'CentralHostPort');
my $timeout = $conf->must_get_val(ATTR=>'CentralHostTimeout');

#
# Build directories if needed.
#
my @dirlist;
foreach $mtype (@mtypes){
	foreach $recv (@nodes){
		next if(!($raddr=$conf->get_val(NODE=>$recv,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		foreach $send (@nodes){
			next if(!($saddr=$conf->get_val(NODE=>$send,
							TYPE=>$mtype,
							ATTR=>'ADDR')));
			push @dirlist, "$datadir/$mtype/$raddr/$saddr";
		}
	}
}
die "No valid paths in mesh?" if(!defined(@dirlist));
mkpath(\@dirlist,0,0775);

chdir $datadir || die "Unable to chdir to $datadir";

#
# setup server socket.
#
my $proto = getprotobyname('tcp');
socket(Server,PF_INET,SOCK_STREAM,$proto) or die "socket: $!";
setsockopt(Server, SOL_SOCKET, SO_REUSEADDR, pack("l",1))
					or die "setsockopt: $!";
bind(Server,sockaddr_in($port,INADDR_ANY)) or die "bind: $!";
listen(Server,SOMAXCONN)			or die "listen: $!";

my $waitedpid = 0;
my $paddr;

my ($reset,$die);
my $serverset = 1;
my (@dead_children,%children);
my $pid;

sub catch{
	my $signame = shift;

	if($signame =~ /HUP/){
		warn "Handling SIG$signame... Stop processing...\n";
		kill 'TERM', (keys %children);
		$reset = 1;
	}
	elsif($signame =~ /CHLD/){
		if(($pid = wait) != -1){
			my @tarr = ($pid,$?);
			if(exists $children{$pid}){
				push @dead_children, \@tarr
			}
			else{
				# Not a child we spawned intentionally...
				# Don't "die" to force exception handling.
				return;
			}
		}
	}
	else{
		$die = 1;
		kill $signame, (keys %children);
	}
	#
	# Die from here so that perl exception handling happens. (This is how
	# we get perl to return from "accept" on a signal... EINTR doesn't
	# seem to happen...)
	#
	die "SIG$signame\n";
}

sub handle_req;

$SIG{CHLD} = $SIG{HUP} = $SIG{TERM} = $SIG{INT} = \&catch;

while(1){
	my ($func);

	$@ = '';
	if($reset || $die){
		close(Server) if($serverset);
		$serverset = 0;
		undef $paddr;
		$func = "sleep";
		eval {sleep;} if((keys %children) > 0);
	}else{
		$func = "accept";
		eval{
			$paddr = accept(Client,Server);
		};
	}
	for($@){
		(/^$/ ||
		/^SIG/)		and $!=0,last;
		die "$func(): $!";
	}

	#
	# Not a connection - do error handling.
	#
	if(!defined($paddr)){
		while(@dead_children > 0){
			my $cpid = shift @dead_children;
			my ($pid,$status) = @$cpid;
			delete $children{$pid};
			syslog('debug',"PID#$pid exited with status $status");
		}

		if($reset){
			next if((keys %children) > 0);
			next if($serverset);
			warn "Restarting...\n";
			exec $FindBin::Bin."/".$FindBin::Script, @SAVEARGV;
		}

		die "Exiting...\n" if($die);

		next;
	}

	#
	# Handle the new connection
	#
	my($port,$iaddr) = sockaddr_in($paddr);


	$pid = handle_req(\*Client,$iaddr);
	$children{$pid} = 1;
	close Client;
}

sub child_catch{
	my $signame = shift;

	$die = 1;

	return;
}

sub read_req{
	my ($fh) = @_;
	my %req;
}

sub do_req{
	undef;
}

sub write_response{
	undef;
}

sub handle_req{
	my ($fh,$iaddr) = @_;

	my $pid = fork;

	# error
	die "fork(): $!" if(!defined($pid));

	# parent
	return $pid if($pid);

	# child continues
	$die = 0;
	$SIG{CHLD} = 'IGNORE';
	$SIG{HUP} = $SIG{TERM} = $SIG{INT} = \&child_catch;

	syslog('info',"connect from [",inet_ntoa($iaddr),"] at port: $port");

	my($rin,$rout,$ein,$eout,$nfound);

	$rin = '';
	vec($rin,$fh->fileno,1) = 1;
	$ein = $rin;

REQ_LOOP:
	while(1){
		last if($die);
		($nfound) = select($rout=$rin,undef,$eout=$ein,$timeout);
		last if(vec($eout,$fh->fileno,1));
		last if(!vec($rout,$fh->fileno,1));
		last if($die);
		
		my(%req) = read_req($fh);
		last if($die);
		#
		# Once we start doing the request - we don't die until
		# after trying to write the response.
		#
		my(%response) = undef;
		%response = do_req if(%req);
		next if(%response && write_response($fh,%response));
		last;
	}

	$fh->close;
	exit(0);
1;
}
