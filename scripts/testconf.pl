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
#	File:		testconf.pl
#
#	Author:		Jeff Boote
#			Internet2
#
#	Date:		Wed Sep 25 09:18:23  2002
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
use OWP;

my $conf = new OWP::Conf('192.168.1.1',"$FindBin::Bin");

my($key);

foreach $key (sort keys %$conf){
	my($val);
	if(ref($conf->{$key}) eq "ARRAY"){
		$val = "";
		foreach (@{$conf->{$key}}){
			$val .= $_." ";
		}
	}
	else{
		$val = $conf->{$key};
	}
		
	print "$key		$val\n";
}

1;
