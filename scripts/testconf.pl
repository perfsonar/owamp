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

my $conf = new OWP::Conf(
		CONFDIR	=> "$FindBin::Bin",
		);

my($key);

print $conf->dump;

#
# test get_val functionality...
#
my(@mtypes,$mtype,@nodes,$node,$adj,$val,$naddr,$aaddr);
@mtypes = $conf->must_get_val(ATTR=>'MESHTYPES');
@nodes = $conf->get_val(ATTR=>'MESHNODES');

#
# test loop... This mimics a weathermap building function by building
# the paths needed to fetch the data for ONLY adjacent nodes.
#
print "\nWEATHERMAP VALUE FETCHING EXAMPLE\n";
foreach $node (@nodes){
	foreach $adj ($conf->get_val(NODE=>$node,ATTR=>'ADJNODES')){
		print "$adj ==>> $node\n";
		# init "warning" value to "ok"
		foreach (@mtypes){
			next if(!$conf->get_val(NODE=>$node,
						TYPE=>$_,
						ATTR=>'MESH'));
			next if(!$conf->get_val(NODE=>$adj,
						TYPE=>$_,
						ATTR=>'MESH'));

#			$naddr = $conf->get_val(NODE=>$node,
#						TYPE=>$_,
#						ATTR=>'ADDR');
#			$aaddr = $conf->get_val(NODE=>$adj,
#						TYPE=>$_,
#						ATTR=>'ADDR');
#			if(defined($naddr) && defined($aaddr)){
				# set "warning" value to worst of current
				# value, or value from here.
			print "DataRoot/$_/$node/$adj/LossAndVarience\n"
#			}
		}
		# Color $adjnode -->> $node arrow with "warning" value.
	}
}

#
# test loop... This mimics a grid building function by fetching
# all pairs for a given mesh-type.
#
print "\nGRID VALUE FETCHING EXAMPLE\n";
MESH:
foreach $mtype (@mtypes){
	print "Mesh: $mtype\n";
	foreach $node (@nodes){
		next if(!$conf->get_val(NODE=>$node,
					TYPE=>$mtype,
					ATTR=>'MESH'));
		print "$node:\t";
		foreach $adj (@nodes){
			next if(!$conf->get_val(NODE=>$adj,
						TYPE=>$mtype,
						ATTR=>'MESH'));
			if($node eq $adj){	# don't test with self.
				print "     ";
			}
			else{
				print "$adj ";
			}

#			$naddr = $conf->get_val(NODE=>$node,
#						TYPE=>$mtype,
#						ATTR=>'ADDR');
#			$aaddr = $conf->get_val(NODE=>$adj,
#						TYPE=>$mtype,
#						ATTR=>'ADDR');
#			if(defined($naddr) && defined($aaddr)){
				# fetch grid value/color from here.
#			print "DataRoot/$mtype/$node/$adj/LossAndVarience\n"
#			}
		}
		print "\n";
	}
}

1;
