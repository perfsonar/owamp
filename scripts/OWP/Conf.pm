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
#			To add additional "scalar" parameters, just start
#			using them. If the new parameter is
#			a BOOL then also add it to the BOOL hash here. If the
#			new parameter is an array then add it to the ARRS
#			hash.
#
#	Usage:
#
#			my $conf = new OWP::Conf([
#						NODE	=>	nodename,
#						CONFDIR =>	path/to/confdir,
#						])
#			NODE will default to ($node) = ($hostname =~ /^.*-(/w)/)
#			CONFDIR will default to $HOME
#
#			The config files can have sections that are
#			only relevant to a particular system/node/addr by
#			using the pseudo httpd.conf file syntax:
#
#			<OS=$regex>
#			osspecificsettings	val
#			</OS>
#
#			The names for the headings are OS and Host.
#			$regex is a text string used to match uname -s,
#			and uname -n. It can contain the wildcard
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
use FindBin;
package OWP::Conf;

$Conf::REVISION = '$Id$';
$Conf::VERSION='1.0';
$Conf::CONFPATH='~';			# default dir for config files.
$Conf::GLOBALCONFENV='OWPGLOBALCONF';
$Conf::DEVCONFENV='OWPCONF';
$Conf::GLOBALCONFNAME='owmesh.conf';

#
# This hash is used to privide default values for "some" parameters.
#
my %DEFS = (
	DEFSECRET		=>	'abcdefgh12345678',
	SECRETNAME		=>	'DEFSECRET',
	SECRETNAMES		=>	['DEFSECRET'],
	MDCMD			=>	'/sbin/md5',	# FreeBSD
	MDCMDFIELD		=>	3,		# FreeBSD
	CENTRALHOST		=>	'netflow.internet2.edu',
	CENTRALHOSTUSER		=>	'owamp',
	CENTRALUPLOADDIR	=>	'/owamp/upload',
	UPTIMESENDTOADDR	=>	'netflow.internet2.edu',
	UPTIMESENDTOPORT	=>	2345,
	DATADIR			=>	'/data',
	OWAMPDVARDIR		=>	'/var/run',
	OWAMPDPIDFILE		=>	'owampd.pid',
	OWAMPDINFOFILE		=>	'owampd.info',
	UPTIME_DB               =>      'uptime.dat',
	OWPBINDIR		=>	"$FindBin::Bin",
	CONFDIR			=>	"$Conf::CONFPATH/",
	SEPARATOR               =>      ',',
);

# Opts that are boolean.
# (These options will be set if the word is by itself, or if the value
# is anything other than false/off/no.)
my %BOOLS = (
	DEBUG		=>	1,
	VERBOSE		=>	1,
);

# Opts that are arrays.
# (These options are automatically split with whitespace - and the return
# is set as an array reference. These options can also show up on more
# than one line, and the values will append onto the array.)
my %ARRS = (
	SECRETNAMES	=>	1,
	MESHNODES	=>	1,
	MESHTYPES	=>	1,
	ADJNODES	=>	1,
	DIGESTRESLIST	=>	1,
);

# Opts that in effect create sub opt hashes.
#
# The keys here actually define new syntax for the config file. The values
# are an array of names that are valid names for the new key.
# A very ugly description of this would be:
# <"KEY"="any one of @{$HASHOPTS{"KEY"}}">
# </"KEY">
my %HASHOPTS = (
	NODE		=>	"MESHNODES",
	DIGESTRES	=>	"DIGESTRESLIST",
	MESH		=>	"MESHTYPES",
);

my %PATHOPTS = (
	DATADIR			=>	1,
	OWAMPDVARDIR		=>	1,
	OWPBINDIR		=>	1,
	CONFDIR			=>	1,
	CENTRALDATADIR		=>	1,
);

sub new {
	my($class,@initialize) = @_;
	my $self = {};

	bless $self,$class;

	$self->init(@initialize);

	return $self;
}

sub resolve_path{
	my($self,$path) = @_;
	my($home,$user,$key);
	
	if(($path =~ m#^~/#o) || ($path =~ m#^~$#o)){
		$home = $ENV{"HOME"} || $ENV{"LOGDIR"} || (getpwuid($<))[7] ||
					die "Can't find Home Directory!";
		$path =~ s#^\~#$home#o;
	}
	elsif(($user) = ($path =~ m#^~([^/]+)/.*#o)){
		$home = (getpwnam($user))[7];
		$path = $home.substr($path,length($user)+1);
	}

	while( ($key) = ($path =~ m#\$([^\/]+)#o)){
		$path =~ s/\$$key/$ENV{$key}/g;
	}
	while( ($key) = ($path =~ m#\$\{([^\}]+)\}#o)){
		$path =~ s/\$\{$key\}/$ENV{$key}/g;
	}

	return $path;
}

# grok a single line from the config file, and adding that parameter
# into the hash ref passed in, unless skip is set.
sub load_line{
	my($self,$line,$href,$skip) = @_;
	my($pname);

	$_ = $line;

	return 1 if(/^\s*#/); # comments
	return 1 if(/^\s*$/); # blank lines

	# reset
	if(($pname) = /^\!(\w+)\s+/o){
		$pname =~ tr/a-z/A-Z/;
		delete ${$href}{$pname} if(!defined($skip));
		return 1;
	}
	# bool
	if(($pname) = /^(\w+)\s*$/o){
		$pname =~ tr/a-z/A-Z/;
		${$href}{$pname} = 1 if(!defined($skip));
		return 1;
	}
	# assignment
	if((($pname,$_) = /^(\w+)\s+(.*)/o)){
		return 1 if(defined($skip));
		$pname =~ tr/a-z/A-Z/;
		if(defined($BOOLS{$pname})){
			if(!/off/oi && !/false/oi && !/no/oi){
				${$href}{$pname} = 1;
			}
		}
		elsif(defined($ARRS{$pname})){
			push @{${$href}{$pname}}, split;
		}
		else{
			${$href}{$pname} = $_;
		}
		return 1;
	}

	return 0;
}

sub load_regex_section{
	my($self,$line,$file,$fh,$type,$match) = @_;
	my($start,$end,$exp,$skip);

	# set start to expression matching <$type=($exp)>
	$start = sprintf "^<%s\\s\*=\\s\*\(\\S\+\)\\s\*>\\s\*", $type;

	# return 0 if this is not a BEGIN section <$type=$exp>
	return 0 if(!(($exp) = ($line =~ /$start/i)));

	# set end to expression matching </$type>
	$end = sprintf "^<\\\/%s\\s\*>\\s\*", $type;

	# check if regex matches for this expression
	# (If it doesn't match, set skip so syntax matching will grok
	# lines without setting hash values.)
	$exp =~ s/([^\w\s-])/\\$1/g;
	$exp =~ s/\\\*/.\*/g;
	$exp =~ s/\\\?/./g;
	if($match =~ !/$exp/){
		$skip = 1;
	}

	#
	# Grok all lines in this sub-section
	#
	while(<$fh>){
		last if(/$end/i);
		die "Syntax error $file:$.:\"$_\"" if(/^</);
		next if $self->load_line($_,$self,$skip);
		# Unknown format
		die "Syntax error $file:$.:\"$_\"";
	}
	return 1;
}

sub load_subhash{
	my($self,$line,$file,$fh) = @_;
	my($type,$start,$end,$name,$found,$skip,%subhash);

	HOPTS:
	foreach (keys %HASHOPTS){
		# set start to expression matching <$type=($name)>
		$start = sprintf "^<%s\\s\*=\\s\*\(\\S\+\)\\s\*>\\s\*", $_;
		if(($name) = ($line =~ /$start/i)){
			$type = $_;
			last HOPTS;
		}
	}
	# return 0 if this is not a BEGIN section <$type=$name>
	return 0 if(!defined($name));
	$name =~ tr/a-z/A-Z/;

	# set end to expression matching </$type>
	$end = sprintf "^<\\\/%s\\s\*>\\s\*", $type;

	# check if value matches for one of the values in HASHOPTS{$type}
	# (If it doesn't match, print a warning and set skip so syntax
	# matching will grok lines without setting hash values.)
	$found = 0;
	if(defined($self->{$HASHOPTS{$type}})){
		HVAR:
		foreach (@{$self->{$HASHOPTS{$type}}}){
			/^$name$/	and $found = 1, last HVAR;
		}
	}
	if(!$found){
		$skip = 1;
		warn "$file:$.:<$type=$name> section ignored...",
			" $name is not in $HASHOPTS{$type}";
	}

	#
	# Grok all lines in this sub-section
	#
	while(<$fh>){
		last if(/$end/i);
		die "Syntax error $file:$.:\"$_\"" if(/^</);
		next if $self->load_line($_,\%subhash,$skip);
		# Unknown format
		die "Syntax error $file:$.:\"$_\"";
	}
	%{$self->{$name}} = %subhash if($found);
	return 1;
}

sub load_file{
	my($self,$file,$node) = @_;
	my($sysname,$hostname) = POSIX::uname();

	my($pname,$pval,$key);
	open PFILE, "<".$file || die "Unable to open $file";
	GLOBAL:
	while(<PFILE>){
		#
		# regex matches
		#

		# HOSTNAME
		next if($self->load_regex_section($_,$file,\*PFILE,"HOST",
								$hostname));
		# OS
		next if($self->load_regex_section($_,$file,\*PFILE,"OS",
								$sysname));
		# sub-hash's
		next if($self->load_subhash($_,$file,\*PFILE));

		# global options
		next if $self->load_line($_,$self);

		die "Syntax error $file:$.:\"$_\"";
	}

	1;
}

sub init {
	my($self,%args) = @_;
	my($confdir,$nodename);
	my($name,$file,$key);
	my($sysname,$hostname) = POSIX::uname();
#	my $hostname = 'nms2-ipls.internet2.edu';

	ARG:
	foreach (keys %args){
		$name = $_;
		$name =~ tr/a-z/A-Z/;
		if($name ne $_){
			$args{$name} = $args{$_};
			delete $args{$_};
		}
		/^confdir$/oi	and $confdir = $args{$name}, next ARG;
		/^node$/oi	and $nodename = $args{$name}, next ARG;
	}

	if(!defined($nodename)){
		($nodename) = ($hostname =~ /^[^-]*-(\w*)/o) and
			$nodename =~ tr/a-z/A-Z/;
		$args{'NODE'} = $nodename if(defined($nodename));
	}

	#
	# Global conf file
	#
	if(defined($ENV{$Conf::GLOBALCONFENV})){
		$file = $self->resolve_path($ENV{$Conf::GLOBALCONFENV});
	}elsif(defined($confdir)){
		$file = $self->resolve_path($confdir.'/'.
							$Conf::GLOBALCONFNAME);
	}
	else{
		$file = $self->resolve_path(
				$DEFS{CONFDIR}.'/'.$Conf::GLOBALCONFNAME);
	}
	if(-e $file){
		$self->{'GLOBALCONF'} = $file
	}else{
		die "Unable to open Global conf:$file";
	}
	$self->load_file($self->{'GLOBALCONF'},$nodename);

	undef $file;
	if(defined($ENV{$Conf::DEVCONFENV})){
		$file = $self->resolve_path($ENV{$Conf::DEVCONFENV});
	}
	if(defined($file) and -e $file){
		$self->{'DEVNODECONF'} = $file
	}
	$self->load_file($self->{'DEVNODECONF'},$nodename)
		if defined($self->{'DEVNODECONF'});

#
#	args passed in as initializers over-ride everything else.
#
	foreach $key (keys %args){
		$self->{$key} = $args{$key};
	}

#
#	hard coded	(this modules fallbacks)
#
	foreach $key (keys(%DEFS)){
		$self->{$key} = $DEFS{$key} if(!defined($self->{$key}));
	}

	foreach $key (keys %PATHOPTS){
		$self->{$key} = $self->resolve_path($self->{$key})
						if(defined($self->{$key}));
	}

	1;
}

sub get_ref {
	my($self,%args) = @_;
	my($type,$attr,$hopt,$name,@subhash,$ref);

	ARG:
	foreach (keys %args){
		/^attr$/oi	and $attr = $args{$_}, next ARG;
		/^type$/oi	and $type = $args{$_}, next ARG;
		foreach $hopt (keys %HASHOPTS){
			if(/^$hopt$/i){
				$name = $args{$_};
				$name =~ tr/a-z/A-Z/;
				if(defined($self->{$name})){
					push @subhash, $self->{$name};
				}
				next ARG;
			}
		}
		die "Unknown named parameter $_ passed into get_ref";
	}

	return undef if(!defined($attr));

	$attr .= $type if(defined($type));
	$attr =~ tr/a-z/A-Z/;

	foreach (@subhash){
		$ref = ${$_}{$attr} if(defined(${$_}{$attr}));
	}
	$ref = $self->{$attr} if(!defined($ref));

	return $ref;
}

#
# This is a convienence routine that dies with
# an error message if the value isn't retrievable.
#
sub get_val{
	my($self,%args)	= @_;
	my($ref);

	for ($ref = $self->get_ref(%args)){
		return undef if(!defined($_));
		/SCALAR/	and return $$ref;
		/HASH/		and return %$ref;
		/ARRAY/		and return @$ref;
		die "Invalid value in hash!?" if(ref($ref));
		# return actual value
		return $ref;
	}

	# not reached
	return undef;
}

#
# This is a convienence routine that dies with
# an error message if the value isn't retrievable.
#
sub must_get_val{
	my($self,%args)	= @_;
	my($ref);

	for ($ref = $self->get_ref(%args)){
		# undef:break out and report error.
		last if(!defined($_));
		/SCALAR/	and return $$ref;
		/HASH/		and return %$ref;
		/ARRAY/		and return @$ref;
		die "Invalid value in hash!?" if(ref($ref));
		# return actual value.
		return $ref;
	}

	my($emsg) = "";
	$emsg.="$_=>$args{$_}, " for (keys %args);
	my($dummy,$fname,$line) = caller;
	die "Conf::must_get_val($emsg) undefined, called from $fname\:$line\n";
}

sub dump_hash{
	my($self,$href,$pre)	=@_;
	my($key);
	my($rtnval) = "";

	KEY:
	foreach $key (sort keys %$href){
		my($val);
		$val = "";
		for (ref $href->{$key}){
			/^$/	and $rtnval.= $pre.$key."=$href->{$key}\n",
					next KEY;
			/ARRAY/	and $rtnval.= $pre.$key."=\[".
					join(',',@{$href->{$key}})."\]\n",
					next KEY;
			/HASH/ and $rtnval.=$pre.$key."[\n".
				$self->dump_hash($href->{$key},"$pre\t").
					$pre."]\n",
					next KEY;
			die "Invalid hash value!";
		}
	}

	return $rtnval;
}


sub dump{
	my($self)	= @_;

	return $self->dump_hash($self,"");
}

# Returns a list of crucial directories and filenames for the given resolution.
# $datadirname is the link's data directory
# $rel_dir is its (www) relative directory
# $filename is only useful with mode 2, where it gives a relative
# name for the summary line
# $mode indicates whether the summary file is needed.
sub get_names_info {
    my ($self, $mtype, $recv, $sender, $res, $mode) = @_;
    my $rel_dir = $self->get_rel_path($mtype, $recv, $sender);
    my $datadirname = join('/', $self->{'CENTRALUPLOADDIR'}, $rel_dir, $res);

    my $full_www = join('/', $self->{'CENTRALWWWDIR'}, $rel_dir);

    my $summary_file = ($mode == 1)? undef : "$full_www/last_summary";

    my $www_reldir = "$rel_dir/$res";

    return ($datadirname, $summary_file, $full_www);
}

# Make a full www path out of the relative one.
sub get_rel_path {
    my ($self, $mtype, $recv, $sender) = @_;
    return "$mtype/$recv/$sender";
}

1;
