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
use Getopt::Std;
use POSIX;
use IPC::Open3;
use File::Path;
use FindBin;
use lib ("$FindBin::Bin");
use OWP;

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

my $options = "";
$options.=$options{$_} foreach (keys %options);
my %setopts;
getopts($options,\%setopts);
foreach (keys %optnames){
	$defaults{$optnames{$_}} = $setopts{$_} if(defined($setopts{$_}));
}

if(!defined($defaults{"NODE"})){
	my $hostname = (POSIX::uname())[1];
#	my $hostname = 'nms2-ipls.internet2.edu';
	my $nodename;
	die "Unable to determine nodename!"
		if(!(($nodename) = $hostname =~ /^[^-]*-(\w*)/o));
	$defaults{"NODE"} = $nodename;
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
# local data/path information
#
my $datadir = $conf->must_get_val(NODE=>$me,ATTR=>"DataDir");
my $powcmd = $conf->must_get_val(NODE=>$me,ATTR=>"OWPBinDir");
$powcmd .= "/";
$powcmd .= $conf->must_get_val(ATTR=>"powcmd");

#
# pid2info - used to determine nature of child process that dies.
# node2pids - used to send sig to powstreams that need to restart based on
#		uptime messages.
my(%pid2info,%node2pids,$pid,$dir);

#
# setup loop - build the directories needed for the mesh defs.
#
my @dirlist;
foreach $mtype (@mtypes){
	next if(!($myaddr=$conf->get_val(NODE=>$me,TYPE=>$mtype,ATTR=>'ADDR')));
	foreach $node (@nodes){
		next if($me eq $node);
		next if(!($oaddr=$conf->get_val(NODE=>$node,
						TYPE=>$mtype,
						ATTR=>'ADDR')));
		push @dirlist, "$mtype/$myaddr/$oaddr";
	}
}
die "No valid paths in mesh?" if(!defined(@dirlist));

mkpath((map {join '/',$datadir,$_} @dirlist),0,0775);

chdir $datadir || die "Unable to chdir to $datadir";

# catch_sig should push dead child pid's onto @dead_children
my @dead_children;
$SIG{INT} = $SIG{HUP} = $SIG{CHLD} = \&catch_sig;

# setup pipe - read side used by send_data, write side used by all
# powsteam children.
my($rfd,$wfd) = POSIX::pipe();

#
# send_data first adds all files in dirlist onto it's workque, then forks
# and returns. (As powsteam finishes files, send_data adds each file
# to it's work que.)
$pid = send_data($conf,$rfd,@dirlist);
@{$pid2info{$pid}} = ("send_data");

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
		open \*CHWFD, ">&=$wfd" || die "Can't fdopen write end of pipe";
		open \*CHRFD, "<$devnull" || die "Can't open $devnull";
		$pid = open3("<&CHRFD",">&CHWFD",">&STDERR",@cmd);
		die "Can't exec $cmd" if(!defined($pid));
		@{$pid2info{$pid}} =
				("powstream",$mtype,$me,$myaddr,$node,$oaddr);
		push @{$node2pids{$node}},$pid;
	}
}

my $reset = 0;
my $newsend = 0;
while(1){

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
	}

	if($reset){
		my @alive = keys %pid2info;
		next if(@alive > 0);
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
		kill 'TERM', keys %pid2info;
		$reset = 1;
		return;
	}

	die "Someone sent $signame";
}

sub sys_readline{
	my($fh) = @_;
	my $char;
	my $read;
	my $fname = "";

	while(1){
		$read = sysread($fh,$char,1);
		die "sysread: $!" if(!defined($read));
		next if($read < 1);
		return $fname if($char eq "\n");
		$fname .= $char;
	}
}

sub send_file{
	my($conf,$fname) = @_;

	print "SEND_DATA:$fname\n" if(defined($debug));
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

	my $pid = fork;

	# error
	die "Can't fork send_data: $!" if(!defined($pid));

	#parent
	return $pid if($pid);

	# child continues.
	$SIG{INT} = $SIG{HUP} = $SIG{CHLD} = 'DEFAULT';
	open STDIN, ">&=$rfd" || die "Can't fdopen write end of pipe";

	my($rin,$rout,$ein,$eout,$timeout,$nfound);

	$rin = '';
	vec($rin,$rfd,1) = 1;
	$ein = $rin;

SEND_FILES:
	while(1){

		if(defined(@flist) && (@flist > 0)){
			$timeout = 0;
		}
		else{
			undef $timeout;
		}

		while($nfound = select($rout=$rin,undef,$eout=$ein,$timeout)){
#			die "send_data:Error reading input: $!" if($eout);
			my $newfile = sys_readline(*STDIN);
			push @flist, $newfile;
			next SEND_FILES;
		}

		next if(!defined(@flist) || (@flist < 1));
		
		shift @flist if(send_file($conf,$flist[0]));
	}
}

1;
