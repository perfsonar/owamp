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
use POSIX;
use IPC::Open3;
use File::Path;
use FileHandle;
use OWP;
use OWP::RawIO;
use OWP::Syslog;
use Sys::Syslog;
use Digest::MD5;
use Socket;
use IO::Socket;
use DB_File;
use Fcntl qw(:flock);
require 'sys/syscall.ph';

my @SAVEARGV = @ARGV;
my %options = (
	CONFDIR		=> "c:",
	NODE		=> "n:",
	FOREGROUND	=> "f",
	);
my %optnames = (
	c		=> "CONFDIR",
	n		=> "NODE",
	f		=> "FOREGROUND",
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

# Add -f flag for re-exec - don't need to re-daemonize.
push @SAVEARGV, '-f' if(!defined($setopts{'f'}));

$defaults{"NODE"} =~ tr/a-z/A-Z/
	if defined($defaults{"NODE"});

my $conf = new OWP::Conf(%defaults);

# setup syslog
local(*MYLOG);
my $slog = tie *MYLOG, 'OWP::Syslog',
		facility	=> $conf->must_get_val(ATTR=>'SyslogFacility'),
		log_opts	=> 'pid',
		setlogsock	=> 'unix';
# make die/warn goto syslog, and also to STDERR.
$slog->HandleDieWarn();
undef $slog;	# Don't keep tie'd ref's around unless you need them...

#
# fetch "global" values needed.
#
my($mtype,$node,$myaddr,$oaddr);
my $debug = $conf->get_val(ATTR=>'DEBUG');
my $foreground = $conf->get_val(ATTR=>'FOREGROUND');
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
# receiving uptime reports on...
#
my $uptimeport = $conf->must_get_val(NODE=>$me,ATTR=>'UPTIMESENDTOPORT');
my $udpmsglen = $conf->must_get_val(ATTR=>'UpTimeMaxMesgLen') + 0;

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
my(%pid2info,%node2pids,$dir);

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
		push @dirlist, "$mtype/$me/$node";
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

my($UptimeSocket) = IO::Socket::INET->new(
				LocalPort	=>	$uptimeport,
				Type		=>	SOCK_DGRAM,
				Proto		=>	'udp',
				ReuseAddr	=>	1,
				Reuse		=>	1) ||
		die "Unable to create udp socket for uptimes: $!";

my($MD5) = new Digest::MD5 ||
			die "Unable to create md5 context";

if(!$debug && !$foreground){
	daemonize(PIDFILE => 'powmaster.pid') ||
		die "Unable to daemonize process";
}

# setup pipe - read side used by send_data, write side used by all
# powsteam children.
my($rfd,$wfd) = POSIX::pipe();
local(*WRITEPIPE);
open WRITEPIPE, ">&=$wfd" || die "Can't fdopen write end of pipe";


#
# send_data first adds all files in dirlist onto it's workque, then forks
# and returns. (As powsteam finishes files, send_data adds each file
# to it's work que.)
my $pid = send_data($conf,$rfd,@dirlist);
@{$pid2info{$pid}} = ("send_data");
$pid = live_update(@addrlist);
@{$pid2info{$pid}} = ("live_update");

#
# powstream setup loop - creates a recv powstream to all other nodes.
# sets the STDOUT of powstream to point at the send_data process.
# (powstream outputs the filenames it produces on stdout.)
#
foreach $mtype (@mtypes){
	warn "Starting Mesh=$mtype\n" if(defined($debug));
	next if(!($myaddr=$conf->get_val(NODE=>$me,TYPE=>$mtype,ATTR=>'ADDR')));

	foreach $node (@nodes){
		my $starttime;
		next if($me eq $node);
		warn "Starting Node=$node\n" if(defined($debug));

		next if(!($oaddr=$conf->get_val(NODE=>$node,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		$starttime = OWP::Utils::time2owptime(time);
		$pid = powstream($mtype,$myaddr,$node,$oaddr);
		push @{$node2pids{$node}},$pid;
		@{$pid2info{$pid}} =
			("powstream",$starttime,$mtype,$myaddr,$node,$oaddr);
	}
}


my ($reset,$die,$sigchld) = (0,0,0);


sub catch_sig{
	my ($signame) = @_;

	return if !defined $signame;

	if($signame =~ /CHLD/){
		$sigchld++;
	}
	elsif($signame =~ /HUP/){
		$reset++;
	}
	else{
		$die++;
	}

	die "SIG$signame\n" if($^S);

	return;
}

my $block_mask = new POSIX::SigSet(SIGCHLD,SIGHUP,SIGTERM,SIGINT);
my $old_mask = new POSIX::SigSet;
sigprocmask(SIG_BLOCK,$block_mask,$old_mask);
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = \&catch_sig;

#
# Main control loop. Gets uptime reports from all other nodes. If it notices
# a node has restarted since a current powstream has been notified, it sends
# a HUP to that powstream to make it reset tests with that node.
# This loop also watches all child processes and restarts them as necessary.
MESSAGE:
while(1){
	my $funcname;
	my $fullmsg;
	my $peeraddr;

	$@ = '';
	if($sigchld){
		undef $peeraddr;
	}
	elsif($reset || $die){
		undef $UptimeSocket;
		undef $peeraddr;
		if($reset == 1){
			$reset++;
			warn "Handling SIGHUP... Stop processing...\n";
			kill 'TERM', keys %pid2info;
			next; # SIGCHLD shows up during kill - even if blocked.
		}
		if($die == 1){
			$die++;
			warn "Exiting... Deleting sub-processes...\n";
			kill 'TERM', keys %pid2info;
			next; # SIGCHLD shows up during kill - even if blocked.
		}
		$funcname = "sigsuspend";
		# Wait for children to exit
		if((keys %pid2info) > 0){
			eval{
				sigsuspend($old_mask);
			};
		}
	}
	else{
		$funcname = "recv";
		eval{
			return if(sigprocmask(SIG_SETMASK,$old_mask) != 0);
			$peeraddr = $UptimeSocket->recv($fullmsg,$udpmsglen,0);
			sigprocmask(SIG_BLOCK,$block_mask);
		};
	}
	for($@){
		(/^$/ || /^SIG/)	and last;
		die "$funcname(): $!";
	}

	#
	# Signal received - update run-state.
	#
	if(!$peeraddr){

		if($sigchld){
			my $wpid;
			$sigchld=0;

			while(($wpid = waitpid(-1,WNOHANG)) > 0){
				next unless (exists $pid2info{$wpid});

				my $info = $pid2info{$wpid};
				syslog('debug',"$$info[0]:$wpid exited: $?");

				delete $pid2info{$wpid};

				next if($reset || $die);

				# restart everything if send_data died.
				if($$info[0] =~ /send_data/){
					kill 'HUP', $$;
				}
				elsif($$info[0] =~ /live_update/){
					warn "Restarting live_update!";
					$pid = live_update(@addrlist);
					@{$pid2info{$pid}} = ("live_update");
				}
				elsif($$info[0] =~ /powstream/){
					shift @$info;
					shift @$info;
					# $$info[2] is now "node"
					warn "Restart powstream->$$info[2]:!";

					# remove old pid from list
					foreach (@{$node2pids{$$info[2]}}){
						if(/^$pid$/){
							undef $_;
							last;
						}
					}

					my $starttime =
						OWP::Utils::time2owptime(time);
					$pid = powstream(@$info);
					push @{$node2pids{$$info[2]}},$pid;
					@{$pid2info{$pid}} =
						("powstream",$starttime,@$info);
				}
			}
		}

		if($reset){
			next if((keys %pid2info) > 0);
			next if(defined $UptimeSocket);
			warn "Restarting...\n";
			exec $FindBin::Bin."/".$FindBin::Script, @SAVEARGV;
		}

		if($die){
			next if((keys %pid2info) > 0);
			die "Dead\n"
		}

		next;
	}

	#
	# Process the UDP message.
	#

	my %msg = ();
	my ($key,$val);

	$MD5->reset;

	my @lines = split '\n',$fullmsg;
	while($_ = shift @lines){
		last if /^$/;
		if(($key,$val) = /^(\w+)\s+(.*)/o){
			$msg{$key} = $val;
			$MD5->add($_);
			next;
		}
		warn "Invalid UDP uptime message received";
		next MESSAGE;
	}
	if(!defined $msg{'SECRETNAME'}){
		warn "No UDP secret?";
		next;
	}

	# fetch secret for validation
	my $secret = $conf->get_val(ATTR=>$msg{'SECRETNAME'});
	if(!$secret){
		warn "Invalid secretname";
		next;
	}

	$MD5->add($secret);
	if($MD5->hexdigest ne shift @lines){
		warn "Unable to validate uptime message:bad hash";
		next;
	}

	warn "Extra UDP message?" if(@lines > 0);

	# $msg now contains a validated uptime message.

	$node = $msg{'NODE'};
	next unless($node && $node2pids{$node});

	# fetch "uptime" pairs. This process is only interested in the
	# "last" uptime, to make sure that it is "before" the powstream
	# was started/signalled.
	my @newuptimes = ();
	@newuptimes = split '_',$msg{'UPTIMEINTERVALS'}
		if(defined $msg{'UPTIMEINTERVALS'});
	if(!($#newuptimes % 2)){
		warn "Invalid uptimes in UDP message";
		next;
	}

	foreach $pid (@{$node2pids{$node}}){
		if(!$pid2info{$pid}){
			warn "\$node2pids and \$pid2info mismatch!";
			next;
		}

		if($newuptimes[-2] > ${$pid2info{$pid}}[1]){
			kill 'HUP', $pid;
			${$pid2info{$pid}}[1] = $newuptimes[-2];
		}
	}

}

my($SendServer) = undef;

sub OpenServer{
	return if(defined $SendServer);

	eval{
		local $SIG{'__DIE__'} = sub{die $_[0];};
		local $SIG{'__WARN__'} = sub{die $_[0];};
		$SendServer = IO::Socket::INET->new(
				PeerAddr	=>	$central_host,
				PeerPort	=>	$central_port,
				Type		=>	SOCK_STREAM,
				TimeOut		=>	$timeout,
				Proto		=>	'tcp');
	};

	if($@){
		warn "Unable to contact Home($central_host)\n";
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
	my($fh,%req) = @_;
	my(%resp);

	OpenServer;
	return undef if(!$SendServer);

	my($line) = "OWP 1.0";
	$MD5->reset;
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					LINE=>$line,
					MD5=>$MD5,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	foreach (keys %req){
		return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					LINE=>"$_\t$req{$_}",
					MD5=>$MD5,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	}
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server));
	$MD5->add($secret);
	return undef if(!sys_writeline(FILEHANDLE=>$SendServer,
					TIMEOUT=>$timeout,
					CALLBACK=>\&fail_server,
					LINE=>$MD5->hexdigest));
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

	$MD5->reset;
	my($pname,$pval);
	while(1){
		$_ = sys_readline(FILEHANDLE=>$SendServer,TIMEOUT=>$timeout);
		if(defined $_){
			last if(/^$/); # end of message
			$MD5->add($_);
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
	$MD5->add($secret);
	if($MD5->hexdigest ne
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
	my($fname) = @_;
	my(%req,$response);
	local *SENDFILE;

	print "SEND_DATA:$fname\n" if defined($debug);

	open SENDFILE, "<".$fname || die "Unable to open $fname";
	binmode SENDFILE;

	# compute the md5 of the file.
	$MD5->reset;
	$MD5->addfile(*SENDFILE);
	$req{'FILEMD5'} = $MD5->hexdigest();

	$req{'FILESIZE'} = sysseek SENDFILE,0,SEEK_END;
	return undef
		if(!$req{'FILESIZE'} || !sysseek SENDFILE,0,SEEK_SET);

	# seek the file to the beginning for transfer
	sysseek SENDFILE,0,SEEK_SET;

	# Set all the req options.
	$req{'OP'} = 'TXFR';
	$req{'FNAME'} = $fname;
	$req{'SECRETNAME'} = $secretname;

	return undef if(!($response = txfr(\*SENDFILE,%req)));

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
					grep {/$suffix$/} readdir(DIR);
		closedir DIR;
	}
	#
	# Sort the list by "start time" of the sessions instead of
	# by directory so data is sent to central server in a more
	# time relevant way.
	#
	if(@flist){
		sub bystart{
			my ($astart) = ($a =~ m#/(\d+)_\d+$suffix$#);
			my ($bstart) = ($b =~ m#/(\d+)_\d+$suffix$#);

			return $astart <=> $bstart;
		}
		@flist = sort bystart @flist;
	}

	my $pid = fork;

	# error
	die "Can't fork send_data: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues.
	$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = 'DEFAULT';
	$SIG{PIPE} = 'IGNORE';
	my $nomask = new POSIX::SigSet;
	exit if(sigprocmask(SIG_SETMASK,$nomask) != 0);

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
		
		if(send_file($flist[0],$MD5)){
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
		$contacts{$sin} = "$ip:$port";
	}

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

	#
	# liveupdate database.
	#
	my %state;
	my $fh = new FileHandle "$updatedb.lck", O_RDWR|O_CREAT;

	die "Unable to lock liveupdate db $updatedb: $!"
		unless($fh && flock($fh,LOCK_EX));
	my $db = tie %state,'DB_File',$updatedb,O_RDWR|O_CREAT,0660,$DB_HASH ||
		die "Unable to open liveupdate db $updatedb: $!";

	my $pid = fork;

	# error
	die "Can't fork live_update: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues.
	my($bzzt) = 0;
	$SIG{INT} = $SIG{TERM} = $SIG{HUP} = $SIG{CHLD} = 'DEFAULT';
	$SIG{PIPE} = 'IGNORE';
	$SIG{ALRM} = sub{$bzzt++;};


	my @intervals = ();
	@intervals = split /_/,$state{$me}
		if defined $state{$me};
	die "Invalid uptime pairs from db: @intervals"
		if((@intervals > 0) && !($#intervals % 2)); # Must be pairs

	my $block_mask = new POSIX::SigSet(SIGALRM);
	my $nomask = new POSIX::SigSet;
	# block SIGALRM
	sigprocmask(SIG_BLOCK,$block_mask);
	# initialize timer to go off in one usec, and then every
	# $senduptimeinterval.
	$in_timer = pack($itimer_t,$senduptimeinterval+0,0,0,1);
	syscall(&SYS_setitimer,0,$in_timer,$out_timer) &&
		die "syscall(setitimer) failed!: $!";

	my($starttime,$owampdpid);
	while(1){
		# wait for sigalrm to go off.
		while(!$bzzt){
			sigsuspend($nomask);
		}
		$bzzt = 0;
		# If we don't know the pid/starttime or if the pid is invalid
		if(!$owampdpid || !$starttime || !kill(0,$owampdpid)){
			# get new info, and see if the new info works.
			($starttime,$owampdpid) = get_owp_info($owampdinfofile);
			next if(!$starttime || !$owampdpid);
			if(!kill(0,$owampdpid)){
				warn "owampd doesn't appear to be running...";
				next;
			}

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
		$state{$me} = join '_', @intervals;
		$db->sync;

		my($key,$line,$msg,%msg);
		$msg{'NODE'} = $me;
		$msg{'SECRETNAME'} = $secretname;
		$msg{'UPTIMEINTERVALS'} = $state{$me};

		$MD5->reset;
		$msg= "";
		foreach $key (keys %msg){
			$line = "$key\t$msg{$key}";
			$MD5->add($line);
			$msg .= $line."\n";
		}
		$MD5->add($secret);
		$msg .= "\n".$MD5->hexdigest;

		my($toaddr);
		foreach $toaddr (keys %contacts){
			print "SEND_UPTIME:$contacts{$toaddr}\n"
				if defined($debug);
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

sub powstream{
	my($mtype,$myaddr,$node,$oaddr)	= @_;
	local(*CHWFD,*CHRFD);
	my $val;
	my @cmd = ($powcmd,"-p","-S",$myaddr);

	push @cmd, ("-i", $val) if($val = $conf->get_val(MESH=>$mtype,
							ATTR=>'OWPINTERVAL'));
	push @cmd, ("-c", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPSESSIONFILESIZE'));
	push @cmd, ("-L", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPLOSSTHRESH'));
	push @cmd, ("-I", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPSESSIONDURATION'));
	push @cmd, ("-s", $val) if($val = $conf->get_val(MESH=>$mtype,
						ATTR=>'OWPPACKETSIZE'));
	push @cmd, ("-d","$mtype/$me/$node",$oaddr);

	my $cmd = join " ", @cmd;
	warn "Executing: $cmd" if(defined($debug));

	open \*CHWFD, ">&WRITEPIPE" || die "Can't dup pipe";
	open \*CHRFD, "<$devnull" || die "Can't open $devnull";
	my $powpid = open3("<&CHRFD",">&CHWFD",">&STDERR",@cmd) ||
		die "Can't exec $cmd";
	return $powpid;
}



1;
