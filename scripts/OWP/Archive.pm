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
#	File:		OWPArchive.pm
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Fri Oct 18 11:20:13 MDT 2002
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
require 5.005;
use strict;
package OWP::Archive;

$Archive::REVISION = '$Id$';
$Archive::VERSION='1.0';

sub new {
	my($class,@initialize) = @_;
	my $self = {};

	bless $self,$class;

	$self->init(@initialize);

	return $self;
}

sub init {
	my($self,%args) = @_;
	my($datadir);

	ARG:
	foreach (keys %args){
		my $name = $_;
		$name =~ tr/a-z/A-Z/;
		if($name ne $_){
			$args{$name} = $args{$_};
			delete $args{$_};
		}
		# Add each "init" var here
		/^datadir$/oi	and $datadir = $args{$name}, next ARG;
	}

	die "DATADIR undefined" if(!defined $datadir);

	return;
}

sub add{
	my($self,%args) = @_;

	die "FILE arg is required" if(!exists $args{'FILE'});

	return 1;
}

sub delete{
	my($self,%args) = @_;

	die "FILE arg is required" if(!exists $args{'FILE'});

	# Check to make sure FILE timestamp is not earlier than
	# "valid_time" for the "directory".

	return 1;
}

sub valid_time{
	my($self,%args) = @_;

	# VALID_TIME is the time data has been valided to: All data before
	# this timestamp is "valid" all data after is "unknown". Unknown
	# data my have "delete" called on them later.
	# ("valid" files would then be ready to go to "deep" archive.)
	die "VALID_TIME arg is required" if(!exists $args{'VALID_TIME'});
	die "DIRECTORY arg is required" if(!exists $args{'DIRECTORY'});

	return 1;
}

1;
