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
use OWP::Archive;
use OWP::Utils;
use OWP::Digest;
use Sys::Syslog;
use File::Basename;
use Fcntl ':flock';
use GDBM_File;
use IO::Socket;

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
# Initialize digesting info
#
my @reslist = sort $conf->must_get_val(ATTR=>'DIGESTRESLIST');
my $digestcmd = $conf->must_get_val(ATTR=>'OWPBinDir');
$digestcmd .= "/";
$digestcmd .= $conf->must_get_val(ATTR=>'digestcmd');
my $sessionsuffix = $conf->must_get_val(ATTR=>'SessionSuffix');
my $digestsuffix = $conf->must_get_val(ATTR=>'DigestSuffix');

#
# data path information
#
my $datadir = $conf->must_get_val(ATTR=>'CentralDataDir');

#
# archive setup
#
my $archive = OWP::Archive->new(DATADIR=>$datadir);

#
# deamon values
#
my $port = $conf->must_get_val(ATTR=>'CentralHostPort');
my $dbfile = $conf->must_get_val(ATTR=>'CentralPerDirDB');

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
			foreach (@reslist){
				push @dirlist,
					"$datadir/$mtype/$raddr/$saddr/$_";
			}
		}
	}
}
die "No valid paths in mesh?" if(!@dirlist);
mkpath(\@dirlist,0,0775);

chdir $datadir || die "Unable to chdir to $datadir";

#
# setup server socket.
#
my $Server = IO::Socket::INET->new(
			LocalPort	=>	$port,
			Proto		=>	'tcp',
			Type		=>	SOCK_STREAM,
			ReuseAddr	=>	1,
			Reuse		=>	1,
			Timeout		=>	$timeout,
			Listen		=>	SOMAXCONN) or die;

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
		undef $Server;
		undef $paddr;
		$func = "sleep";
		eval {sleep;} if((keys %children) > 0);
	}else{
		$func = "accept";
		eval{
			$paddr = $Server->accept;
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
			next if(defined $Server);
			warn "Restarting...\n";
			exec $FindBin::Bin."/".$FindBin::Script, @SAVEARGV;
		}

		die "Exiting...\n" if($die);

		next;
	}

	#
	# Handle the new connection
	#

	$pid = handle_req($paddr);
	$children{$pid} = 1;
	undef $paddr;
}

sub combine_digests{
	my($dir,$base,$res,$reslist,$state) = @_;

	# made it to the largest resolution - return ok.
	return 1 if(@$reslist < 1);

	# fetch the resolution of file we are building here.
	my($buildres) = shift @$reslist;

	# fetch the current list of "pending" files at the lower
	# resolution that is used to build this file.
	my @buildfiles = ();
	if(exists $state->{$res."PENDING"}){
		@buildfiles = split /:/,$state->{$res."PENDING"};
	}
	if(@buildfiles < 1){
		# first one.. can just return.
		$state->{$res."PENDING"} = $base;
		return 1;
	}

	# set buildstart to the beginning of the new file
	# set buildend to the last time allowed in this file.
	my ($buildstart) = split '_',$buildfiles[0];
	my $buildend = OWP::Utils::owptimeadd($buildstart,$buildres);

	# filestart/fileend are the begin/end times for the new file
	# that was added at the "lower" resolution.
	my($filestart,$fileend) = split '_',$base;

	my ($laststart) = split '_',$buildfiles[$#buildfiles];
	if($filestart <= $laststart){
		warn "Ignoring OUT-OF-ORDER File: ${dir}/${res}/${base}${digestsuffix}";
		return 1;
	}

	#
	# If the start time of the new file is within the window
	# of the buildstart/buildend, then add it to the list.
	push @buildfiles, $base if($filestart <= $buildend);

	#
	# Set newstart/newend to the actual values for the
	# datarange available.
	my($dummy,$newend) = split '_',$buildfiles[$#buildfiles];
	my $newstart = $buildstart;

	#
	# If the newer lowres file escapes out of the window, then
	# it is time to process the list into a new file at the
	# larger resolution.
	if($fileend > $buildend){
		if(!OWP::Digest::merge(
		"${dir}/${buildres}/${newstart}_${newend}${digestsuffix}",
			map {"${dir}/${res}/${_}${digestsuffix}"} @buildfiles)){
			return 0;
		}

		if(!combine_digests($dir,"${newstart}_${newend}",
						$buildres,$reslist,$state)){
			unlink "${dir}/${buildres}/${newstart}_${newend}${digestsuffix}";
			return 0;
		}
		@buildfiles = ();
	}

	push @buildfiles, $base if($filestart > $buildend);

	if(@buildfiles > 0){
		$state->{$res."PENDING"} = join ':', @buildfiles;
	}
	else{
		delete $state->{$res."PENDING"};
	}

	return 1;
}

sub clean_files{
	my($tstamp,$dir,$res,$state) = @_;

	my($period) = $conf->get_val(DIGESTRES=>$res,ATTR=>'SAVEPERIOD');
	$period = $conf->get_val(DIGESTRES=>$res,ATTR=>'PLOTPERIOD')
		if(!defined $period);
	if(!defined $period){
		warn("$dir/$res files not cleaned!");
		return;
	}

	# save period is defined as 0 - no cleaning.
	return if(!$period);

	$tstamp = OWP::Utils::owptimeadd($tstamp,-$period,-$res);
	my @pending = ();
	@pending = split /:/,$state->{$res."PENDING"}
		if(exists $state->{$res."PENDING"});
	if(@pending > 0){
		my($start) = split '_',$pending[0];
		if(!defined $start){
			warn("Invalid ${res}PENDING value: $pending[0]");
			return;
		}
		$tstamp = ($tstamp < $start)?$tstamp:$start;
	}

	local *RESDIR;

	if(!opendir(RESDIR,"$dir/$res")){
		warn("Unable to opendir $dir/$res: $!");
		return;
	}

	foreach (sort grep {/$digestsuffix$/} readdir(RESDIR)){
		my($start) = split '_',$_;

		next if(!defined $start);	# skip non-matching files
		last if($start >= $tstamp);

		unlink "$dir/$res/$_" ||
			warn("Unable to unlink $dir/$res/$_: $!");
	}
	closedir(RESDIR);

	return;
}

sub read_req{
	my ($fh,$md5) = @_;
	my %req;
	my $vers;

	$md5->reset;

	# read version - ignored for now.
	$_ = sys_readline(FILEHANDLE=>$fh,TIMEOUT=>$timeout);
	$_ = "" if !defined $_;
	die "Invalid request!: $_" if(!(($vers) = /OWP\s+(\d+)/));
	$md5->add($_);

	while(($_ = sys_readline(FILEHANDLE=>$fh,TIMEOUT=>$timeout))){
		my($pname,$pval);

		last if(/^$/); # end of message
		$md5->add($_);
		next if(/^\s*#/); # comments
		next if(/^\s*$/); # blank lines.

		if(($pname,$pval) = /^(\w+)\s+(.*)/o){
			$pname =~ tr/a-z/A-Z/;
			$req{$pname} = $pval;
			next;
		}

		# Invalid message!
		die "Invalid request from socket!";
	}
	die "No secretname!" if(!exists $req{'SECRETNAME'});
	$req{'SECRET'} = $conf->must_get_val(ATTR=>$req{'SECRETNAME'});
	$md5->add($req{'SECRET'});
	die "Invalid auth hash!"
		if($md5->hexdigest ne sys_readline(FILEHANDLE=>$fh,
							TIMEOUT=>$timeout));
	die "Invalid end Message!" if("" ne sys_readline(FILEHANDLE=>$fh,
							TIMEOUT=>$timeout));

	return %req;
}

sub do_req{
	my($fh,$md5,%req) = @_;
	my(%resp,$buf);
	local (*TFILE);

	die "Invalid OP request"
		if(!exists $req{'OP'} || $req{'OP'} ne 'TXFR');

	die "Invalid filename"
		if(!exists $req{'FNAME'});

	die "Invalid filesize"
		if(!exists $req{'FILESIZE'});
	die "Invalid file MD5"
		if(!exists $req{'FILEMD5'});

	my $len = $req{'FILESIZE'};

	open TFILE, ">$req{'FNAME'}.i" ||
		die "Unable to open file $req{'FNAME'}";

	RLOOP:
	while($len){
		# all read/write errors are fatal - make the client reconnect.
		my($written,$buf,$rlen,$offset);
		undef $rlen;
		eval{
			local $SIG{ALRM} = sub{die "alarm\n"};
			alarm $timeout;
			$rlen = sysread $fh,$buf,$len;
			alarm 0;
		};
		if(!defined $rlen){
			next RLOOP if(($! == EINTR) && ($@ ne "alarm\n"));
			unlink "$req{'FNAME'}.i";
			die "Read error from socket: $!\n";
		}
		$len -= $rlen;
		$offset=0;
		WLOOP:
		while($rlen){
			undef $written;
			eval{
				local $SIG{ALRM} = sub{die "alarm\n"};
				alarm $timeout;
				$written = syswrite TFILE, $buf, $rlen, $offset;
				alarm 0;
			};
			if(!defined $written){
				next WLOOP if(($! == EINTR)&&($@ ne "alarm\n"));
				unlink "$req{'FNAME'}.i";
				die "Write error to file $req{'FNAME'}.i: $!";
			}
			$rlen -= $written;
			$offset += $written;
		}
	}
	close TFILE;

	# close and reopen to ensure flushing of file, and because
	# I don't want to try and mix read/sysread here.
	if(!open TFILE, "<$req{'FNAME'}.i"){
		unlink "$req{'FNAME'}.i";
		die "Unable to open $req{'FNAME'} for md5 check: $!";
	}

	$md5->reset;
	$md5->addfile(*TFILE);
	close TFILE;
	if($md5->hexdigest ne $req{'FILEMD5'}){
		unlink "$req{'FNAME'}.i";
		die "Failed File MD5!";
	}

	my($base,$dir) = fileparse($req{'FNAME'},$sessionsuffix);
	# remove trailing '/'
	$dir =~ s#/$##;

	# GDBM_WRCREATE locks the file.
	my %state;
	if(!tie %state, 'GDBM_File', "$dir/$dbfile", &GDBM_WRCREAT, 0660){
		unlink "$req{'FNAME'}.i";
		die "Unable to open db file $dir/$dbfile: $!";
	}

	my($start,$end) = split /_/,$base;

	die "Invalid filename datestamps" if(!defined $start || !defined $end);

	my(@intervals,$i);
	@intervals = split /_/,$state{'UPTIMEINTERVALS'}
		if defined $state{'UPTIMEINTERVALS'};
	if($i = valid_session($start,$end,@intervals)){
		# remove up/down pairs that are no longer needed.
		while($i>1){
			shift @intervals;
			$i--;
		}
		$state{'UPTIMEINTERVALS'} = join '_', @intervals
			if(defined @intervals);

		rename "$req{'FNAME'}.i",$req{'FNAME'} ||
			die "Unable to rename $req{'FNAME'}";

		if(!$archive->add(FILE=>$req{'FNAME'})){
			unlink $req{'FNAME'};
			die "Unable to archive $req{'FNAME'}";
		}

		my(@res) = @reslist;
		my($res) = shift @res;
		if(system($digestcmd,$req{'FNAME'},
				"${dir}/${res}/${base}${digestsuffix}") != 0){
			unlink $req{'FNAME'};
			die "Unable to digest raw session data";
		}

		if(!combine_digests($dir,$base,$res,\@res,\%state)){
			unlink $req{'FNAME'};
			unlink "$dir/$res/$base$digestsuffix";
			die "Unable to climb digest tree";
		}

		my($tstamp) = OWP::Utils::time2owptime(time);
		foreach $res (@reslist){
			clean_files($tstamp,$dir,$res,\%state);
		}
	}else{
		warn "$req{'FNAME'} ignored - invalid session";
		unlink "$req{'FNAME'}.i";
	}


	untie %state;

	$resp{'STATUS'} = 'OK';
	$resp{'FILEMD5'} = $req{'FILEMD5'};
	$resp{'SECRET'} = $req{'SECRET'};

	return %resp;
}

sub write_response{
	my($fh,$md5,%resp)	= @_;

	my $line = "OWP 1.0";
	my $secret = $resp{'SECRET'};

	delete $resp{'SECRET'};

	$md5->reset;
	return undef if(!sys_writeline(FILEHANDLE=>$fh,
					MD5=>$md5,
					TIMEOUT=>$timeout,
					LINE=>$line));
	foreach (keys %resp){
		return undef if(!sys_writeline(FILEHANDLE=>$fh,
						MD5=>$md5,
						TIMEOUT=>$timeout,
						LINE=>"$_\t$resp{$_}"));
	}
	return undef if(!sys_writeline(FILEHANDLE=>$fh,
					TIMEOUT=>$timeout));
	$md5->add($secret);
	return undef if(!sys_writeline(FILEHANDLE=>$fh,
					MD5=>$md5,
					TIMEOUT=>$timeout,
					LINE=>$md5->hexdigest));
	return undef if(!sys_writeline(FILEHANDLE=>$fh,
					TIMEOUT=>$timeout));

	return 1;
}

sub child_catch{
	my $signame = shift;

	$die = 1;

	return;
}

sub handle_req{
	my ($fh) = @_;

	my $pid = fork;

	# error
	die "fork(): $!" if(!defined($pid));

	# parent
	return $pid if($pid);

	# child continues
	undef $Server;
	my $md5 = new Digest::MD5 ||
		die "Unable to create md5 context";

	$die = 0;
	$SIG{CHLD} = 'DEFAULT';
	$SIG{HUP} = $SIG{TERM} = $SIG{INT} = \&child_catch;

	syslog('info',"connect from [".$fh->peerhost."] at port: $port");

	my($rin,$rout,$ein,$eout,$nfound);

	$rin = '';
	vec($rin,$fh->fileno,1) = 1;
	$ein = $rin;


REQ_LOOP:
	while(1){
		last if($die);
		($nfound) = select($rout=$rin,undef,$eout=$ein,$timeout);
		last if($die);
		last if(vec($eout,$fh->fileno,1));
		last if(!vec($rout,$fh->fileno,1));
		
		my(%req) = read_req($fh,$md5);
		last if($die);
		#
		# Once we start doing the request - we don't die until
		# after trying to write the response.
		#
		my(%response);
		undef %response;
		%response = do_req($fh,$md5,%req) if(%req);
		next if(defined %response &&
			write_response($fh,$md5,%response));
		last;
	}

	$fh->close;
	exit(0);
1;
}
