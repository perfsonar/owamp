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
use OWP;
use OWP::Syslog;
use OWP::RawIO;
use OWP::Archive;
use OWP::Utils;
use OWP::Digest;
use Sys::Syslog;
use File::Basename;
use Fcntl ':flock';
use FileHandle;
use IO::Socket;
use DB_File;
use Carp qw(cluck);

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
my $serverport = $conf->must_get_val(ATTR=>'CentralHostPort');
my $dbfile = $conf->must_get_val(ATTR=>'CentralPerDirDB');
my $vtimefile = $conf->must_get_val(ATTR=>'CentralPerDirValidFile');
my $uptimedb = $datadir . "/" . $conf->must_get_val(ATTR=>'UpTimeDBFile');
my $udpmsglen = $conf->must_get_val(ATTR=>'UpTimeMaxMesgLen') + 0;
my $uptimeport = $conf->must_get_val(ATTR=>'UpTimeSendToPort');

my $timeout = $conf->must_get_val(ATTR=>'CentralHostTimeout');

#
# Build directories if needed.
#
my($mtype,$recv,$send,$raddr,$saddr,$res);
my %nodeupdate;	# hash vals contain list of dirs to update for each "node".
my @dirlist; # list of directories that must exist.
foreach $mtype (@mtypes){
	foreach $recv (@nodes){
		next if(!($raddr=$conf->get_val(NODE=>$recv,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		foreach $send (@nodes){
			next if(!($saddr=$conf->get_val(NODE=>$send,
							TYPE=>$mtype,
							ATTR=>'ADDR')));
			push @{$nodeupdate{$send}},
				"$datadir/$mtype/$raddr/$saddr";

			foreach $res (@reslist){
				push @dirlist,
					"$datadir/$mtype/$raddr/$saddr/$res";
			}
		}
	}
}
die "No valid paths in mesh?" if(!@dirlist);
mkpath(\@dirlist,0,0775);

chdir $datadir || die "Unable to chdir to $datadir";

my (%children);

# just in case...
use constant MAX_UPTIMES_RESTARTS => 5;
my $uppid = uptimes(%nodeupdate);
$children{$uppid} = 'uptimes';
my $uprestarts = 0;

#
# setup server socket.
#
my $Server = IO::Socket::INET->new(
			LocalPort	=>	$serverport,
			Proto		=>	'tcp',
			Type		=>	SOCK_STREAM,
			ReuseAddr	=>	1,
			Reuse		=>	1,
			Timeout		=>	$timeout,
			Listen		=>	SOMAXCONN) or die;

my ($reset,$die,$sigchld,$insig) = (0,0,0,0);

sub catch{
	my $signame = $_;

	return if !defined $signame;

	if($signame =~ /HUP/){
		$reset = 1;
	}
	elsif($signame =~ /CHLD/){
		$sigchld++;
	}
	else{
		$die = 1;
	}
	#
	# If we are in an eval - die from here to make the function return
	# and not automatically restart: ie accept.
	# (protect die from reentrance because it is tied to non-reentrant
	# syslog.)
	#
	if($^S && !$insig){
		$insig = 1;
		die "SIG$signame\n";
		$insig = 0;
	}

	#
	# If we are not in an eval - we have already set our global vars
	# so things should happen properly in the main loop.

	return;
}

sub handle_req;

my $block_mask = new POSIX::SigSet(SIGCHLD,SIGHUP,SIGTERM,SIGINT);
my $old_mask = new POSIX::SigSet;
sigprocmask(SIG_BLOCK,$block_mask,$old_mask);
$SIG{CHLD} = $SIG{HUP} = $SIG{TERM} = $SIG{INT} = \&catch;

while(1){
	my $paddr;
	my ($func);

	$@ = '';
	if($sigchld){
		undef $paddr;
	}elsif($reset || $die){
		undef $Server;
		undef $paddr;
		$func = "sigsuspend";
		if((keys %children) > 0){
			eval{
				sigsuspend($old_mask);
			};
		}
	}else{
		$func = "accept";
		eval{
			return if(sigprocmask(SIG_SETMASK,$old_mask) != 0);
			$paddr = $Server->accept;
			sigprocmask(SIG_BLOCK,$block_mask);
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
		if($reset == 1){
			$reset++;
			warn "Handling SIGHUP... Stop processing...\n";
			kill 'TERM', (keys %children);
		}
		if($die == 1){
			$die++;
			warn "Exiting... Deleting sub-processes...\n";
			kill 'TERM', (keys %children);
		}
		if($sigchld){
			my $wpid;
			while(($wpid = waitpid(-1,WNOHANG)) > 0){
				next unless (exists $children{$wpid});

				syslog('debug',
					"$children{$wpid}:$wpid exited: $?");
				if($children{$wpid} eq 'uptimes' &&
							!$reset && !$die){
					if($uprestarts++>MAX_UPTIMES_RESTARTS){
						warn
					"Uptimes process critical failures!";
						kill 'TERM', $$;
					}
					$uppid = uptimes(%nodeupdate);
					$children{$uppid} = 'uptimes';
				}

				delete $children{$wpid};
			}
			$sigchld=0;
		}

		if($reset){
			next if((keys %children) > 0);
			next if(defined $Server);
			warn "Restarting...\n";
			exec $FindBin::Bin."/".$FindBin::Script, @SAVEARGV;
		}

		if($die){
			next if((keys %children) > 0);
			die "Dead\n";
		}

		next;
	}

	#
	# Handle the new connection
	#

	my $newpid = handle_req($paddr);
	$children{$newpid} = 'handle_req';
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

	my($dummy,$lastend) = split '_',$buildfiles[$#buildfiles];
	if($filestart < $lastend){
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
	my $newend;
	($dummy,$newend) = split '_',$buildfiles[$#buildfiles];
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
	return if !defined $_;
	die "Invalid request!: $_" if(!(($vers) = /OWP\s+(\d+)/));
	$md5->add($_);

	while(($_ = sys_readline(FILEHANDLE=>$fh,TIMEOUT=>$timeout))){
		my($pname,$pval);

		$md5->add($_);
		next if(/^\s*#/); # comments
		next if(/^\s*$/); # blank lines.

		if(($pname,$pval) = /^(\w+)\s+(.*)/o){
			$pname =~ tr/a-z/A-Z/;
			$req{$pname} = $pval;
			next;
		}

		# Invalid message!
		die "Invalid request from socket: $_";
	}
	return if(!defined $_);
	die "No secretname!" if(!exists $req{'SECRETNAME'});
	$req{'SECRET'} = $conf->must_get_val(ATTR=>$req{'SECRETNAME'});
	$md5->add($req{'SECRET'});

	$_ = sys_readline(FILEHANDLE=>$fh,TIMEOUT=>$timeout);
	return if(!defined $_);
	die "Invalid auth hash: $_" if($md5->hexdigest ne $_);

	$_ = sys_readline(FILEHANDLE=>$fh,TIMEOUT=>$timeout);
	return if(!defined $_);
	die "Invalid end Message: $_" if("" ne $_);

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

	my %state;
	my $dbfh = new FileHandle "$dir/$dbfile.lck", O_CREAT|O_RDWR;
	unless($dbfh && flock($dbfh,LOCK_EX)){
		unlink "$req{'FNAME'}.i";
		die "Unable to lock db file $dir/$dbfile: $!";
	}
	if(!tie %state,'DB_File',"$dir/$dbfile",O_CREAT|O_RDWR,0660, $DB_HASH){
		unlink "$req{'FNAME'}.i";
		die "Unable to open db file $dir/$dbfile: $!";
	}

	my($start,$end) = split /_/,$base;

	die "Invalid filename datestamps" if(!defined $start || !defined $end);

	my(@intervals) = ();
	@intervals = split /_/,$state{'UPTIMEINTERVALS'}
		if defined $state{'UPTIMEINTERVALS'};
	if(valid_session($start,$end,\@intervals)){

		rename "$req{'FNAME'}.i",$req{'FNAME'} ||
			die "Unable to rename $req{'FNAME'}";

		my(@res) = @reslist;
		my($res) = shift @res;
		if(system($digestcmd,$req{'FNAME'},
				"${dir}/${res}/${base}${digestsuffix}") != 0){
			unlink $req{'FNAME'};
			die "Unable to digest raw session data";
		}

		if(!$archive->add(FILE=>$req{'FNAME'})){
			unlink $req{'FNAME'};
			die "Unable to archive $req{'FNAME'}";
		}
		# file no longer needed.
		unlink $req{'FNAME'};

		if(!combine_digests($dir,$base,$res,\@res,\%state)){
			unlink "$dir/$res/$base$digestsuffix";
			$archive->delete(FILE=>$req{'FNAME'});
			die "Unable to climb digest tree";
		}

		my($tstamp) = OWP::Utils::time2owptime(time);
		foreach $res (@reslist){
			clean_files($tstamp,$dir,$res,\%state);
		}

		#
		# Update interval information.
		#
		if(@intervals > 1){

			$state{'UPTIMEINTERVALS'} = join '_', @intervals;

			# If file end is before last "uptime" reported,
			# then we can update the "valid" time to the
			# time of the end of the file.
			if($end < $intervals[$#intervals]){
				# inform archive of updated valid_time
				$archive->valid_time(DIRECTORY=>$dir,
							VALID_TIME=>$end);

				# inform "plotting" of updated valid_time
				#
				# using rename to update the "valid_time" file
				# so that it is an "atomic" operation.
				open TFILE, ">$dir/$vtimefile.i"  ||
					warn "Open Error $dir/$vtimefile.i: $!";
				print TFILE "$end";
				close TFILE;
				rename "$dir/$vtimefile.i","$dir/$vtimefile" ||
					warn "Rename $dir/$vtimefile: $!";
			}
		}
	}else{
		warn "$req{'FNAME'} ignored - invalid session";
		unlink "$req{'FNAME'}.i";
	}

	# MUST untie before undef'ing the lock!
	untie %state;
	undef $dbfh;

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
	return if(!sys_writeline(FILEHANDLE=>$fh,
					MD5=>$md5,
					TIMEOUT=>$timeout,
					LINE=>$line));
	foreach (keys %resp){
		return if(!sys_writeline(FILEHANDLE=>$fh,
						MD5=>$md5,
						TIMEOUT=>$timeout,
						LINE=>"$_\t$resp{$_}"));
	}
	return if(!sys_writeline(FILEHANDLE=>$fh,
					TIMEOUT=>$timeout));
	$md5->add($secret);
	return if(!sys_writeline(FILEHANDLE=>$fh,
					MD5=>$md5,
					TIMEOUT=>$timeout,
					LINE=>$md5->hexdigest));
	return if(!sys_writeline(FILEHANDLE=>$fh,
					TIMEOUT=>$timeout));

	return 1;
}

sub child_catch{
	my $signame = shift;

	$die = 1;

	die "SIG$signame caught...\n";
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

	syslog('info',"connect from [".$fh->peerhost."]");

	my($rin,$rout,$ein,$eout,$nfound);

	$rin = '';
	vec($rin,$fh->fileno,1) = 1;
	$ein = $rin;

REQ_LOOP:
	while(1){
		my(%req,%response);
		# accept signals
		eval{
			sigprocmask(SIG_SETMASK,$old_mask);
		};
		last if($die);
		die "\$@ = $@" if($@);
		eval {
			($nfound) =select($rout=$rin,undef,$eout=$ein,$timeout);
		};
		last if($die);
		die "\$@ = $@" if($@);
		last if(vec($eout,$fh->fileno,1));
		last if(!vec($rout,$fh->fileno,1));
		
		undef %req;
		%req = read_req($fh,$md5);
		last if($die);
		#
		# Once we start doing the request - we block sigs until
		# after trying to write the response.
		eval{
			sigprocmask(SIG_BLOCK,$block_mask);
		};
		last if($die);
		die "\$@ = $@" if($@);
		undef %response;
		%response = do_req($fh,$md5,%req) if(defined %req);
		next if(defined %response &&
			write_response($fh,$md5,%response));
		last;
	}

	exit 0;
}

sub update_node{
	my($node,$upref,@dirs)	= @_;
	my($skip,$dir);
	my %state;
	my $fh;

	# $skip is the number of elements to shift off the upref array
	# at the end because the earlier elements are no longer needed.
	# (Initialize it to the max that can be removed, individual
	# dirs that need more will update it.)
	$skip = @$upref - 2;
	SENDDIR:
	while($dir = shift @dirs){
		undef %state;
		# open per-dir database - this locks the directory as well
		# as allowing this process to update the last "valid" time.
		$fh = new FileHandle "$dir/$dbfile.lck", O_CREAT|O_RDWR;
		unless($fh && flock($fh,LOCK_EX)){
			warn "Unable to lock db file $dir/$dbfile: $!";
			$skip = 0;
			next;
		}
		if(!tie %state, 'DB_File', "$dir/$dbfile",O_CREAT|O_RDWR,0660,
								$DB_HASH){
			warn "Unable to open db file $dir/$dbfile: $!";
			$skip = 0;
			next;
		}
		my @intervals = ();
		@intervals = split /_/,$state{'UPTIMEINTERVALS'}
				if defined $state{'UPTIMEINTERVALS'};

		# $validstart will be set to the time that existing
		# files have been validated with. i.e. files with
		# a start time before this time can be ignored.
		# (initialize to 0 so all files are done the first time.)
		my $validstart = 0;
		my @globals = @$upref;
		if(@intervals >0){
			my $index = $#intervals-1;
			$validstart = $intervals[$index];
			my $skipglobals = 0;
			while(@globals > 0){
				# global start is old - skip it.
				next if($globals[0] < $intervals[$index]);
				# global start is new - break and add
				# this and all remaining.
				last if($globals[0] > $intervals[$index]);

				# global start == local start
				# update "end" time, then break and
				# add remaining globals.
				$intervals[$#intervals] = $globals[1];
				shift @globals;
				shift @globals;
				last;
			}
			continue{
				shift @globals;
				shift @globals;
				$skipglobals+=2;
			}
			# keep track of MIN skips so global array can
			# have skipped values removed.
			$skip = ($skip<$skipglobals)?$skip:$skipglobals;
		}
		push @intervals, @globals if(@globals > 0);
		undef @globals;

		if(@intervals < 2){
			warn "No valid intervals for update_node?";
			next;
		}

		my $validend=0;
		my $res;
		foreach $res (@reslist){
			local *RESDIR;

			unless(opendir(RESDIR,"$dir/$res")){
				warn("Unable to opendir $dir/$res: $!");
				next SENDDIR;
			}

			my @lvals = @intervals;
			foreach(sort grep {/$digestsuffix$/} readdir(RESDIR)){
				my($start,$end) = m#(\d+)_(\d+)$digestsuffix$#;

				# skip non-matching files
				next if(!$start || !$end);

				# Skip files that have already been validated
				next if($start < $validstart);

				# $start is before this interval - invalid.
				if($start < $lvals[0]){
					unlink "$dir/$res/$_" ||
					warn("unlink($dir/$res/$_): $!");
					next SENDDIR;
				}

				# $start is after this interval - go to next
				# interval.
				if($start > $lvals[1]){
					last if(@lvals <= 2);
					shift @lvals;
					shift @lvals;
					redo;
				}

				# $start is in this interval, if $end is too,
				# then we can call it valid!
				if($end <= $lvals[1]){
					$validend = ($validend > $end)?
							$validend: $end;
					next;
				}

				# If this is the last interval, it is not
				# possible to validate/invalidate anymore
				# files. (This $end is after the last
				# know uptime.)
				last if(@lvals <= 2);
			}
			closedir(RESDIR);
		}

		$state{'UPTIMEINTERVALS'} = join '_', @intervals;

		# Update VALIDTIME file with end timestamp of last
		# file in the "lowest" res "completely" in the range.
		if($validend){
			local (*TFILE);

			# inform archive of updated valid_time
			$archive->valid_time(DIRECTORY=>$dir,
							VALID_TIME=>$validend);

			# inform "plotting" of updated valid_time
			#
			# using rename to update the "valid_time" file
			# so that it is an "atomic" operation.
			unless(open TFILE, ">$dir/$vtimefile.i"){
				warn "Open Error $dir/$vtimefile.i: $!";
				next;
			}
			print TFILE "$validend";
			close TFILE;
			rename "$dir/$vtimefile.i","$dir/$vtimefile" ||
					warn "Rename $dir/$vtimefile: $!";
			
		}
	}
	# MUST untie before undef'ing the lock!
	continue{
		untie %state if(defined %state);
		undef $fh;
	}
	untie %state if(defined %state);
	undef $fh;

	while($skip--){
		shift @$upref;
	}

	return;
}

sub uptimes{
	my (%node2dirs) = @_;

	my($md5) = new Digest::MD5 ||
		die "Unable to create md5 context";

	my %state;
	my $fh = new FileHandle "$uptimedb.lck", O_CREAT|O_RDWR;
	unless($fh && flock($fh,LOCK_EX)){
		die "Unable to lock node uptime db file $uptimedb: $!";
	}
	my $db = tie(%state,'DB_File',$uptimedb,O_CREAT|O_RDWR,0660,$DB_HASH) ||
		die "Unable to open node uptime db $uptimedb: $!";

	#
	# Create udp socket for receiving uptimes.
	#
	my $UptimeSocket = IO::Socket::INET->new(
				TYPE		=>	SOCK_DGRAM,
				Proto		=>	'udp',
				LocalPort	=>	$uptimeport) ||
		die "Unable to create udp socket for uptimes: $!";

	my $pid = fork;

	# error
	die "Can't fork uptimes: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues...
	$SIG{HUP} = $SIG{TERM} = $SIG{INT} = $SIG{CHLD} = 'DEFAULT';

	my @uptimes;
	my $node;
	foreach $node (keys %node2dirs){
		next if(!defined $state{$node});
		@uptimes = split '_',$state{$node};
		if((@uptimes > 0) && !($#uptimes % 2)){
			warn "Invalid uptimes pairs from db for $node";
			delete $state{$node};
			next;
		}
		next if(@uptimes < 2);
		update_node($node,\@uptimes,@{$node2dirs{$node}});
		$state{$node} = join '_',@uptimes;
	}
	$db->sync;

	my($peeraddr);
	my($fullmsg);
	MESSAGE:
	while($peeraddr = $UptimeSocket->recv($fullmsg,$udpmsglen,0)){
		my %msg = ();
		my ($key,$val);

		$md5->reset;

		my @lines = split '\n',$fullmsg;
		while($_ = shift @lines){
			last if /^$/;
			if(($key,$val) = /^(\w+)\s+(.*)/o){
				$msg{$key} = $val;
				$md5->add($_);
				next;
			}
			warn "Invalid udp message received";
			next MESSAGE;
		}
		if(!defined $msg{'SECRETNAME'}){
			warn "No secret?";
			next;
		}

		my $secret = $conf->get_val(ATTR=>$msg{'SECRETNAME'});
		if(!$secret){
			warn "Invalid secretname";
			next;
		}

		$md5->add($secret);
		if($md5->hexdigest ne shift @lines){
			warn "Invalid secret";
			next;
		}

		warn "More message?" if(@lines > 0);

		next if !($node = $msg{'NODE'});

		# prepare "message" uptime pairs.
		my @newuptimes = ();
		@newuptimes = split '_',$msg{'UPTIMEINTERVALS'}
			if(defined $msg{'UPTIMEINTERVALS'});
		if(!($#newuptimes % 2)){
			warn "Invalid uptimes in message";
			next;
		}

		# fetch db's version of uptime pairs
		@uptimes = ();
		@uptimes = split '_',$state{$node} if(defined $state{$node});
		if((@uptimes > 0) && !($#uptimes % 2)){
			warn "Invalid uptimes pairs from db for $node";
			delete $state{$node};
		}

		# combine db/mesage uptime pairs
		if(@uptimes > 0){
			my $oi = $#uptimes-1;
			while(@newuptimes > 0){
				next if($newuptimes[0] < $uptimes[$oi]);
				last if($newuptimes[0] > $uptimes[$oi]);
				# start times are == update this
				# entry, and then break out of loop
				$uptimes[$#uptimes] = $newuptimes[1];
				shift @newuptimes;
				shift @newuptimes;
				last;
			}
			continue{
				shift @newuptimes;
				shift @newuptimes;
			}
		}
		push @uptimes, @newuptimes if(@newuptimes > 0);

		# update the node with the new uptime information
		next if(@uptimes < 2);
		update_node($node,\@uptimes,@{$node2dirs{$node}});

		# save the new uptime info (update_node modifies
		# the uptimes array so it is only as large as it needs
		# to be. i.e. It deletes older values that are no
		# longer needed.
		$state{$node} = join '_',@uptimes;
		$db->sync;
	}
	die "recv error on udp socket: $!";
}

1;
