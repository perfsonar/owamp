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
#	File:		powmaster.pl
#
#	Author:		Jeff W. Boote
#			Internet2
#
#	Date:		Mon Sep 30 16:38:32 MDT 2002
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
use POSIX qw(SEEK_END SEEK_SET EINTR SIGALRM SIG_BLOCK sigprocmask sigsuspend);
use IPC::Open3;
use File::Path;
use FileHandle;
use OWP;
use OWP::RawIO;
use Digest::MD5;
use Socket;
use IO::Socket;
use GDBM_File;
require 'sys/syscall.ph';
#require 'time.ph';
#require 'sys/time.ph';

my @SAVEARGV = @ARGV;
my %options = (
	CONFDIR		=> "c:",
	NODE		=> "n:",
	);
my %optnames = (
	c		=> "CONFDIR",
	n		=> "NODE",
	);
my %defaults = (
		CONFDIR	=> "$FindBin::Bin",
		);

my $options = join "", values %options;
my %setopts;
getopts($options,\%setopts);
foreach (keys %optnames){
	$defaults{$optnames{$_}} = $setopts{$_} if(defined($setopts{$_}));
}

$defaults{"NODE"} =~ tr/a-z/A-Z/;

my $conf = new OWP::Conf(%defaults);

#
# fetch "global" values needed.
#
my($mtype,$node,$myaddr,$oaddr);
my $debug = $conf->get_val(ATTR=>'DEBUG');
my $devnull = $conf->must_get_val(ATTR=>"devnull");
my $suffix = $conf->must_get_val(ATTR=>"SessionSuffix");

#
# node/mesh values
#
my $me = $conf->must_get_val(ATTR=>'NODE');
my @mtypes = $conf->must_get_val(ATTR=>'MESHTYPES');
my @nodes = $conf->must_get_val(ATTR=>'MESHNODES');

#
# Central server values
#
my $secretname = $conf->must_get_val(NODE=>$me,ATTR=>'SECRETNAME');
my $secret = $conf->must_get_val(ATTR=>$secretname);
my $central_host = $conf->must_get_val(ATTR=>'CENTRALHOST');
my $central_port = $conf->must_get_val(ATTR=>'CENTRALHOSTPORT');
my $timeout = $conf->must_get_val(NODE=>$me,ATTR=>'SendTimeout');

#
# live_update values
#
my $senduptimeinterval = $conf->must_get_val(NODE=>$me,
						ATTR=>'UpTimeSendInterval');
my $senduptimepairs = $conf->must_get_val(NODE=>$me,
						ATTR=>'UpTimeSendPairs');
my $owampdinfofile = $conf->must_get_val(NODE=>$me,ATTR=>'OWAMPDVARDIR');
$owampdinfofile .= '/';
$owampdinfofile .= $conf->must_get_val(NODE=>$me,ATTR=>'OWAMPDINFOFILE');

#
# local data/path information
#
my $datadir = $conf->must_get_val(NODE=>$me,ATTR=>"DataDir");
my $powcmd = $conf->must_get_val(NODE=>$me,ATTR=>"OWPBinDir");
$powcmd .= "/";
$powcmd .= $conf->must_get_val(ATTR=>"powcmd");
my $updatedb = $datadir . "/" . $conf->must_get_val(NODE=>$me,
						ATTR=>'UpTimeDBFile');

#
# pid2info - used to determine nature of child process that dies.
# node2pids - used to send sig to powstreams that need to restart based on
#		uptime messages.
my(%pid2info,%node2pids,$pid,$dir);

#
# setup loop - build the directories needed for the mesh defs.
#		find the addresses for live_update.
#
my @dirlist;
my @addrlist;
foreach $mtype (@mtypes){
	next if(!($myaddr=$conf->get_val(NODE=>$me,TYPE=>$mtype,ATTR=>'ADDR')));
	foreach $node (@nodes){
		next if($me eq $node);
		next if(!($oaddr=$conf->get_val(NODE=>$node,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		push @dirlist, "$mtype/$myaddr/$oaddr";
		my $upaddr = $conf->must_get_val(NODE=>$node,
						ATTR=>'UPTIMESENDTOADDR');
		my $upport = $conf->must_get_val(NODE=>$node,
						ATTR=>'UPTIMESENDTOPORT');
		my @tarr = ($upaddr,$upport);
		push @addrlist, \@tarr;
	}
}
die "No valid paths in mesh?" if(!defined(@dirlist));
die "No valid nodes in mesh?" if(!defined(@addrlist));
mkpath([map {join '/',$datadir,$_} @dirlist],0,0775);

chdir $datadir || die "Unable to chdir to $datadir";

# catch_sig should push dead child pid's onto @dead_children
my @dead_children;
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = \&catch_sig;

# setup pipe - read side used by send_data, write side used by all
# powsteam children.
my($rfd,$wfd) = POSIX::pipe();
local(*WRITEPIPE);
open WRITEPIPE, ">&=$wfd" || die "Can't fdopen write end of pipe";

#
# send_data first adds all files in dirlist onto it's workque, then forks
# and returns. (As powsteam finishes files, send_data adds each file
# to it's work que.)
$pid = send_data($conf,$rfd,@dirlist);
@{$pid2info{$pid}} = ("send_data");
$pid = live_update(@addrlist);
@{$pid2info{$pid}} = ("live_update");

#
# powstream setup loop - creates a recv powstream to all other nodes.
# sets the STDOUT of powstream to point at the send_data process.
# (powstream outputs the filenames it produces on stdout.)
#
foreach $mtype (@mtypes){
	my (@mcmd,$val);

	print "Starting Mesh=$mtype\n" if(defined($debug));
	next if(!($myaddr=$conf->get_val(NODE=>$me,TYPE=>$mtype,ATTR=>'ADDR')));

	@mcmd = ();
	push @mcmd, ($powcmd,"-p","-S",$myaddr);
	push @mcmd, ("-i", $val) if($val = $conf->get_val(MESH=>$mtype,
							ATTR=>'OWPINTERVAL'));
	push @mcmd, ("-c", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPSESSIONFILESIZE'));
	push @mcmd, ("-L", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPLOSSTHRESH'));
	push @mcmd, ("-I", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPSESSIONDURATION'));
	push @mcmd, ("-s", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPPACKETSIZE'));
	foreach $node (@nodes){
		local(*CHWFD,*CHRFD);
		my(@cmd,$cmd);

		print "Starting Node=$node\n" if(defined($debug));

		next if($me eq $node);
		next if(!($oaddr=$conf->get_val(NODE=>$node,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		@cmd = @mcmd;
		$dir = "$mtype/$myaddr/$oaddr";
		push @cmd, ("-d", $dir);
		push @cmd, $oaddr;

		$cmd = join(" ", @cmd);
		print "Executing: $cmd\n" if(defined($debug));
		open \*CHWFD, ">&WRITEPIPE" || die "Can't dup pipe";
		open \*CHRFD, "<$devnull" || die "Can't open $devnull";
		$pid = open3("<&CHRFD",">&CHWFD",">&STDERR",@cmd);
		die "Can't exec $cmd" if(!defined($pid));
		@{$pid2info{$pid}} =
				("powstream",$mtype,$me,$myaddr,$node,$oaddr);
		push @{$node2pids{$node}},$pid;
	}
}

my $reset = 0;
while(1){

	# TODO: This sleep will eventually be replaced with a recv of
	# live_update udp packets from other nodes. If a node sends
	# a time that is "later" than the start time of a current
	# powstream, then the powstream should have a HUP sent to it.
	sleep;
	while(@dead_children > 0){
		my $cpid = shift @dead_children;
		my ($pid,$status) = @$cpid;
		my $info = $pid2info{$pid};

		warn "Dead Child!:$pid:$$info[0]:status $status\n"
			if(defined($debug) or !$reset);
		delete $pid2info{$pid};

		next if($reset);

		# restart everything if send_data died.
		if($$info[0] =~ /send_data/){
			kill 'HUP', $$;
		}

		if($$info[0] =~ /live_update/){
			warn "Restarting live_update!";
			$pid = live_update(@addrlist);
			@{$pid2info{$pid}} = ("live_update");
		}
	}

	if($reset){
		next if((keys %pid2info) > 0);
		warn "Restarting...\n";
		exec $FindBin::Bin."/".$FindBin::Script, @SAVEARGV;
	}
}

sub catch_sig{
	my $signame = shift;

	if($signame =~ /CHLD/){
		my($pid);
		if(($pid = wait) != -1){
			my @tarr = ($pid,$?);
			push @dead_children, \@tarr;
		}
		return;
	}

	if($signame =~ /HUP/){
		warn "Handling SIG$signame... Stop processing...\n";
		kill 'TERM', keys %pid2info;
		$reset = 1;
		return;
	}

	kill $signame, keys %pid2info;
	die "Handling SIG$signame...\n";
}

my($SendServer) = undef;

sub OpenServer{
	return if(defined $SendServer);

	eval{
		$SendServer = IO::Socket::INET->new(
				PeerAddr	=>	$central_host,
				PeerPort	=>	$central_port,
				Type		=>	SOCK_STREAM,
				TimeOut		=>	$timeout,
				Proto		=>	'tcp');
	};

	if($@){
		warn "Unable to contact Home:$central_host: $@";
	}

	return;
}

sub fail_server{
	return undef if(!defined $SendServer);
	
	$SendServer->close;
	undef $SendServer;

	return undef;
}

sub txfr{
	my($fh,$md5,%req) = @_;
	my(%resp);

	OpenServer;
	return undef if(!$SendServer);

	my($line) = "OWP 1.0";
	$md5->reset;
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					LINE=>$line,
					MD5=>$md5,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	foreach (keys %req){
		return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					LINE=>"$_\t$req{$_}",
					MD5=>$md5,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	}
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	$md5->add($secret);
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server,
					LINE=>$md5->hexdigest));
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	my($len) = $req{'FILESIZE'};
	RLOOP:
	while($len){
		# local read errors are fatal
		my ($written,$buf,$rlen,$offset);
		undef $rlen;
		eval{
			local $SIG{ALRM} = sub{die "alarm\n"};
			alarm $timeout;
			$rlen = sysread $fh,$buf,$len;
			alarm 0;
		};
		if(!defined($rlen)){
			die "Timeout reading $req{'FILENAME'}: $!"
				if($@ && ($@ eq "alarm\n"));
			next RLOOP if ($! == EINTR);
			die "System read error: $!\n";
		}
		$len -= $rlen;
		$offset=0;
		WLOOP:
		while($rlen){
			# socket write errors cause eventual retry.
			undef $written;
			eval{
				local $SIG{ALRM} = sub{die "alarm\n"};
				alarm $timeout;
				$written = syswrite $SendServer,$buf,$rlen,
									$offset;
				alarm 0;
			};
			if(!defined($written)){
				return fail_server if($@ && ($@ eq "alarm\n"));
				next WLOOP if($! == EINTR);
				return fail_server;
			}
			$rlen -= $written;
			$offset += $written;
		}
	}

	$md5->reset;
	my($pname,$pval);
	while(1){
		$_ = sys_readline(FILEHANDLE=>$SendServer,TIMEOUT=>$timeout);
		if(defined $_){
			last if(/^$/); # end of message
			$md5->add($_);
			next if(/^\s*#/); # comments
			next if(/^\s*$/); # blank lines

			if(($pname,$pval) = /^(\w+)\s+(.*)/o){
				$pname =~ tr/a-z/A-Z/;
				$resp{$pname} = $pval;
				next;
			}
		}
		# Invalid message!
		warn ("Socket closed or Invalid message from server!");
		return fail_server;
	}
	$md5->add($secret);
	if($md5->hexdigest ne
		sys_readline(FILEHANDLE=>$SendServer,TIMEOUT=>$timeout)){
		warn ("Invalid MD5 for server response!");
		return fail_server;
	}
	if("" ne sys_readline(FILEHANDLE=>$SendServer,TIMEOUT=>$timeout)){
		warn ("Invalid End Message from Server!");
		return fail_server;
	}

	return \%resp;
}

sub send_file{
	my($fname,$md5) = @_;
	my(%req,$response);
	local *SENDFILE;

	print "SEND_DATA:$fname\n" if defined($debug);

	open SENDFILE, "<".$fname || die "Unable to open $fname";
	binmode SENDFILE;

	# compute the md5 of the file.
	$md5->reset;
	$md5->addfile(*SENDFILE);
	$req{'FILEMD5'} = $md5->hexdigest();

	$req{'FILESIZE'} = sysseek SENDFILE,0,SEEK_END;
	return undef
		if(!$req{'FILESIZE'} || !sysseek SENDFILE,0,SEEK_SET);

	# seek the file to the beginning for transfer
	sysseek SENDFILE,0,SEEK_SET;

	# reset md5 context so it can be used for the message verification.
	$md5->reset;

	# Set all the req options.
	$req{'OP'} = 'TXFR';
	$req{'FNAME'} = $fname;
	$req{'SECRETNAME'} = $secretname;

	return undef if(!($response = txfr(\*SENDFILE,$md5,%req)));

	return undef if(!exists $response->{'FILEMD5'} ||
			($response->{'FILEMD5'} ne $req{'FILEMD5'}));

	unlink $fname || warn "unlink: $!";

	return 1;
}

sub send_data{
	my($conf,$rfd,@dirlist)	= @_;

	# @flist is the workque.
	my(@flist,$ldir);
	foreach $ldir (@dirlist){
		local *DIR;
		opendir(DIR,$ldir) || die "can't opendir $_:$!";
		push @flist, map {join '/',$ldir,$_}
					sort grep {/$suffix$/} readdir(DIR);
		closedir DIR;
	}
	#
	# Sort the list by "start time" of the sessions instead of
	# by directory so data is sent to central server in a more
	# digestable way.
	#
	if(@flist){
		sub bystart{
			my ($astart) = ($a =~ m#/(\d+)_\d+$suffix$#);
			my ($bstart) = ($b =~ m#/(\d+)_\d+$suffix$#);

			return $astart <=> $bstart;
		}
		@flist = sort bystart @flist;
	}

	my($md5) = new Digest::MD5 ||
			die "Unable to create md5 context";

	my $pid = fork;

	# error
	die "Can't fork send_data: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues.
	$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = 'DEFAULT';
	$SIG{PIPE} = 'IGNORE';
	open STDIN, ">&=$rfd" || die "Can't fdopen read end of pipe";

	my($rin,$rout,$ein,$eout,$tmout,$nfound);

	$rin = '';
	vec($rin,$rfd,1) = 1;
	$ein = $rin;

SEND_FILES:
	while(1){

		if(defined(@flist) && (@flist > 0)){
			# only poll with select if we have work to do.
			$tmout = 0;
		}
		else{
			undef $tmout;
		}

		if($nfound = select($rout=$rin,undef,$eout=$ein,$tmout)){
			my $newfile = sys_readline();
			push @flist, $newfile;
			next SEND_FILES;
		}

		next if(!defined(@flist) || (@flist < 1));
		
		if(send_file($flist[0],$md5)){
			shift @flist;
		}
		else{
			# upload not working.. wait before trying again.
			sleep $timeout;
		}
	}
}

sub live_update{
	my(@addrlist)	= @_;

	#
	# save only one of each address specification using a hash
	#
	my($addr,%contacts);
	foreach $addr (@addrlist){
		my($sin);
		my($ip,$port) = @$addr;
		$sin = sockaddr_in($port,inet_aton($ip));
		$contacts{$sin} = 1;
	}

	my($md5) = new Digest::MD5 ||
			die "Unable to create md5 context";

	#
	# test syscall setitimer before the fork to make sure syscall
	# works.
	my $itimer_t = 'L4';
	my($in_timer,$out_timer);
	# This will unset any alarm in the main prog...
	$in_timer = $out_timer = pack($itimer_t,0,0,0,0);
	syscall(&SYS_setitimer,0,$in_timer,$out_timer) &&
		die "syscall(setitimer) failed!: $!";

	#
	# Create udp socket for sending updates
	#
	my $SendSocket = IO::Socket::INET->new(
				Type		=>	SOCK_DGRAM,
				Proto		=>	'udp') ||
		die "Unable to create udp socket for live_update: $!";

	my $pid = fork;

	# error
	die "Can't fork send_data: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues.
	my($bzzt) = 0;
	$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = 'DEFAULT';
	$SIG{PIPE} = 'IGNORE';
	$SIG{ALRM} = sub{$bzzt++;};

	#
	# liveupdate database.
	# (Would be nice to do this before fork, but for sematics for
	# locking files makes that risky.)
	#
	my %state;
	tie %state, 'GDBM_File', $updatedb, &GDBM_WRCREAT, 0660 ||
		die "Unable to open liveupdate db $updatedb: $!";

	my @intervals = ();
	@intervals = split /_/,$state{'UPTIMEINTERVALS'}
		if defined $state{'UPTIMEINTERVALS'};
	die "Invalid uptime pairs from db: @intervals"
		if((@intervals > 0) && !($#intervals % 2)); # Must be pairs

	my $block_mask = new POSIX::SigSet(SIGALRM);
	my $old_mask = new POSIX::SigSet;
	# block SIGALRM and fetch current mask
	sigprocmask(SIG_BLOCK,$block_mask,$old_mask);
	# remove SIGALRM from old_mask so it can be used for sigsuspend.
	$old_mask->delset(SIGALRM);
	# initialize timer to go off in one second, and then every
	# $senduptimeinterval.
	$in_timer = pack($itimer_t,$senduptimeinterval+0,0,1,0);
	syscall(&SYS_setitimer,0,$in_timer,$out_timer) &&
		die "syscall(setitimer) failed!: $!";

	my($starttime,$owampdpid);
	while(1){
		# wait for sigalrm to go off.
		while(!$bzzt){
			sigsuspend($old_mask);
		}
		$bzzt = 0;
		# If we don't know the pid/starttime or if the pid is invalid
		if(!$owampdpid || !$starttime || !kill(0,$owampdpid)){
			# get new info, and see if the new info works.
			($starttime,$owampdpid) = get_owp_info($owampdinfofile);
			next if(!$starttime || !$owampdpid);
			next if(!kill(0,$owampdpid));

			if(@intervals == 0 || $intervals[-2] ne $starttime){
				push @intervals, $starttime,
						OWP::Utils::time2owptime(time);
			}else{
				$intervals[$#intervals] =
						OWP::Utils::time2owptime(time);
			}

			while((@intervals >= 2) &&
					(@intervals >= $senduptimepairs)){
				shift @intervals;
				shift @intervals;
			}
		}else{
			$intervals[$#intervals] =
						OWP::Utils::time2owptime(time);
		}
		$state{'UPTIMEINTERVALS'} = join '_', @intervals;

		my($key,$line,$msg,%msg);
		$msg{'NODE'} = $me;
		$msg{'SECRETNAME'} = $secretname;
		$msg{'UPTIMEINTERVALS'} = $state{'UPTIMEINTERVALS'};

		$md5->reset;
		$msg= "";
		foreach $key (keys %msg){
			$line = "$key\t$msg{$key}";
			$md5->add($line);
			$msg .= $line."\n";
		}
		$md5->add($secret);
		$msg .= "\n".$md5->hexdigest."\n";

		my($toaddr);
		foreach $toaddr (keys %contacts){
			$SendSocket->send($msg,0,$toaddr);
		}
	}
}

sub get_owp_info{
	my($infofile) = @_;
	my ($start, $pid);
	local(*INFO);

	# Read owampd start time.
	if(!open INFO, "<$infofile"){
		warn "Could not open $infofile: $!";
		return (undef,undef);
	}

	while(<INFO>){
		if(/^START=(\d+)$/){
			($start) = /^START=(\d+)$/;
			next;
		}
		if(/^PID=(\d+)$/){
			($pid) = /^PID=(\d+)$/;
			next;
		}
	}

	if(!$start){
		warn "Could not find start time in $infofile";
	}
	if(!$pid){
		warn "Could not find pid in $infofile";
	}

	return ($start, $pid)
}

1;
