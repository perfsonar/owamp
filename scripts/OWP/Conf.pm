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
#	File:		OWPConf.pm
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Tue Sep 24 10:40:10  2002
#
#	Description:	
#			This module is used to set configuration parameters
#			for the OWP one-way-ping mesh configuration.
#
#			To add additional configuration parameters just add
#			them to the OPTS hash.  If the new parameter is
#			a BOOL then also add it to the BOOL hash. If the
#			new parameter is an array that itself defines additional
#			parameters, then add it to DEPS.
#	Usage:
#
#			my $conf = new OWP::Conf($addr,$confpath)
#			$addr is required
#			$confpath will default to $HOME
#
#			The config files can have sections that are
#			only relevant to a particular system/node/addr by
#			using the pseudo httpd.conf file syntax:
#
#			<OS=$regex>
#			osspecificsettings	val
#			</OS>
#
#			The names for the headings are OS/Node/Addr.
#			$regex is a text string used to match uname -s,
#			uname -n, and $addr. It can contain the wildcard
#			chars '*' and '?' with '*' matching 0 or more occurances
#			of *anything* and '?' matching exactly 1 occurance
#			of *anything*.
#
#	Environment:
#
#	Files:
#
#	Options:
require 5.005;
use strict;
use POSIX;
package OWP::Conf;

$Conf::REVISION = '$Id$';
$Conf::VERSION='1.0';
$Conf::CONFPATH='~';			# default dir for config files.
$Conf::GLOBALCONFENV='OWPGLOBALCONF';
$Conf::NODECONFENV='OWPNODECONF';
$Conf::GLOBALCONFNAME='owmesh.conf';
$Conf::NODECONFNAME='ownode.conf';

my %OPTS = (
	'DEBUG',		'Debug',
	'VERBOSE',		'Verbose',
	'GLOBALCONF',		'GlobalConf',
	'NODECONF',		'NodeConf',
	'DEFSECRET',		'DefSecret',
	'SECRETNAME',		'SecretName',
	'SECRETNAMES',		'SecretNames',
	'MDCMD',		'MdCmd',
	'MDCMDFIELD',		'MdCmdField',
	'CENTRALHOST',		'CentralHost',
	'CENTRALHOSTUSER',	'CentralHostUser',
	'CENTRALUPLOADDIR',	'CentralUpLoadDir',
	'UPTIMESENDTOADDR',	'UpTimeSendToAddr',
	'UPTIMESENDTOPORT',	'UpTimeSendToPort',
	'NODEDATADIR',		'NodeDataDir',
	'OWAMPDVARPATH',	'OwampdVarPath',
	'OWAMPDPIDFILE',	'OwampdPidFile',
	'OWAMPDINFOFILE',	'OwampdInfoFile',
);

my %DEFS = (
	'DEBUG',		0,
	'VERBOSE',		0,
	'DEFSECRET',		'abcdefgh12345678',
	'SECRETNAME',		'DEFSECRET',
	'SECRETNAMES',		['DEFSECRET'],
	'MDCMD',		'/sbin/md5',	# FreeBSD
	'MDCMDFIELD',		3,		# FreeBSD
	'CENTRALHOST',		'netflow.internet2.edu',
	'CENTRALHOSTUSER',	'owamp',
	'CENTRALUPLOADDIR',	'/owamp/upload/',
	'UPTIMESENDTOADDR',	'netflow.internet2.edu',
	'UPTIMESENDTOPORT',	2345,
	'NODEDATADIR',		'/data',
	'OWAMPDVARPATH',	'/var/run',
	'OWAMPDPIDFILE',	'owampd.pid',
	'OWAMPDINFOFILE',	'owampd.info',
	'OWPCONFDIR',		"$Conf::CONFPATH/",
);

# Opts that are boolean.
my %BOOLS = (
	'DEBUG',		1.0,
	'VERBOSE',		1.0,
);

# Opts that in effect create other opts.
# (These cause another iteration through...)
my %DEPS = (
	'SECRETNAMES',		1,
);

sub new {
	my($class,@initialize) = @_;
	my $self = {};

	bless $self,$class;

	$self->init(@initialize);

	return $self;
}

sub resolve_home{
	my($self,$path) = @_;
	my($home,$user);
	
	
	if(($path =~ m#^~/#o) || ($path =~ m#^~$#o)){
		$home = $ENV{"HOME"} || $ENV{"LOGDIR"} || (getpwuid($<))[7] ||
					die "Can't find Home Directory!";
		$path =~ s#^\~#$home#o;
		return $path;
	}
	elsif(($user) = ($path =~ m#^~([^/]+)/.*#o)){
		$home = (getpwnam($user))[7];
		return $home.substr($path,length($user)+1);
	}

	return $path;
}

sub load_file_section{
	my($self,$line,$file,$fh,$href,$type,$match) = @_;
	my($start,$end,$exp,$doit,$pname,$pval);

	# set start to expression matching <$type=($exp)>
	$start = sprintf "^<%s\\s\*=\\s\*\(\\S\+\)\\s\*>\\s\*", $type;
	# set end to expression matching </$type>
	$end = sprintf "^<\\\/%s\\s\*>\\s\*", $type;

	# return 0 if this is not a BEGIN section <$type=$exp>
	return 0 if(!(($exp) = ($line =~ /$start/i)));
	$exp =~ s/([^\w\s-])/\\$1/g;
	$exp =~ s/\\\*/.\*/g;
	$exp =~ s/\\\?/./g;
	if($match =~ /$exp/){
		$doit = 1;
	}else{
		$doit = 0;
	}
	while(<$fh>){
		last if(/$end/i);
		die "Syntax error $file:$.:\"$_\"" if(/^</);
		next if(/^\s*#/); # comments
		next if(/^\s*$/); # blank lines
		next if(!$doit);
		# assignment
		if((($pname,$pval) = /^(\S+)\s+(.*)/o)){
			$pname =~ tr/a-z/A-Z/;
			${$href}{$pname} = $pval;
			next;
		}
		# bool
		if(($pname) = /^(\S+)\s*$/o){
			$pval = 1;
			${$href}{$pname} = $pval;
			next;
		}
		# Unknown format
		die "Syntax error $file:$.:\"$_\"";
	}
	return 1;
}

sub load_file{
	my($self,$file,$addr) = @_;
	my($sysname,$nodename) = POSIX::uname();

	my(%gprefs,%sprefs,$pname,$pval,$exp,$key);
	open PFILE, "<".$file || die "Unable to open $file";
	GLOBAL:
	while(<PFILE>){
		next if(/^\s*#/); # comments
		next if(/^\s*$/); # blank lines
		# ADDR
		next if($self->load_file_section
				($_,$file,\*PFILE,\%gprefs,"Addr",$addr));
		# NODE
		next if($self->load_file_section
				($_,$file,\*PFILE,\%gprefs,"Node",$nodename));
		# OS
		next if($self->load_file_section
				($_,$file,\*PFILE,\%gprefs,"OS",$sysname));
		# global bool
		if(($pname) = /^(\S+)\s*$/o){
			$pval = 1;
			$gprefs{$pname} = $pval;
			next;
		}
		# global assignment
		if((($pname,$pval) = /^(\S+)\s+(.*)/o)){
			$pname =~ tr/a-z/A-Z/;
			$gprefs{$pname} = $pval;
			next;
		}
		die "Syntax error $file:$.:\"$_\"";
	}
	# load OPTS into self
	foreach $key (keys(%OPTS)){
		$self->{$key} = $gprefs{$key}
					if(defined($gprefs{$key}));
	}
	# load OPTS defined by the dependent opts
	foreach $key (keys(%DEPS)){
		next if(!defined($gprefs{$key}));
		foreach ($gprefs{$key}){
			$self->{$_} = $gprefs{$_}
					if(defined($gprefs{$_}));
		}
	}

	1;
}

sub init {
	my($self,$addr,$confpath,$rest) = @_;
	my($file,$key);

	die "Conf requires an addr specification!" if(!defined($addr));
	if(defined($ENV{$Conf::GLOBALCONFENV})){
		$file = $self->resolve_home($ENV{$Conf::GLOBALCONFENV});
	}elsif(defined($confpath)){
		$file = $self->resolve_home($confpath.'/'.
							$Conf::GLOBALCONFNAME);
	}
	else{
		$file = $self->resolve_home(
				$DEFS{OWPCONFDIR}.'/'.$Conf::GLOBALCONFNAME);
	}
	if(-e $file){
		$self->{'GLOBALCONF'} = $file
	}else{
		die "Unable to open Global conf:$file";
	}

	if(defined($ENV{$Conf::NODECONFENV})){
		$file = $self->resolve_home($ENV{$Conf::NODECONFENV});
	}elsif(defined($confpath)){
		$file = $self->resolve_home($confpath.'/'.$Conf::NODECONFNAME);
	}else{
		$file = $self->resolve_home(
				$DEFS{OWPCONFDIR}.'/'.$Conf::NODECONFNAME);
	}
	if(-e $file){
		$self->{'NODECONF'} = $file
	}

#
#	hard coded	(this modules)
#
	foreach $key (keys(%DEFS)){
		$self->{$key} = $DEFS{$key};
	}
#
#	config files
#
	$self->load_file($self->{'GLOBALCONF'},$addr);
	$self->load_file($self->{'NODECONF'},$addr)
		if defined($self->{'NODECONF'});

#	//	environment
	foreach $key (keys(%OPTS)){
		$self->{$key} = $ENV{$key} if defined($ENV{$key});
	}

	my($bool);
	foreach $bool (keys(%BOOLS)){
		$self->{$bool} = undef if($self->{$bool} =~ /off/oi);
		$self->{$bool} = undef if($self->{$bool} =~ /false/oi);
		$self->{$bool} = undef if($self->{$bool} =~ /no/oi);
	}

	1;
}

1;
