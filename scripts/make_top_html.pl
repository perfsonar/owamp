#!/usr/local/bin/perl -w
#
#      $Id$

use strict;

# This script runs every 1 minute and generates an (almost static)
# HTML page of stat report grids for each mesh.

use constant DEBUG => 1;
use constant VERBOSE => 1;

use FindBin;
use lib ("$FindBin::Bin");
use IO::Handle;
use File::Path;
use CGI qw/:standard/;
use OWP;

$| = 1;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");
my $wwwdir = $conf->{'CENTRALWWWDIR'};

my @mtypes = $conf->get_val(ATTR=>'MESHTYPES');
my @nodes = $conf->get_val(ATTR=>'MESHNODES');

my $dataroot = $conf->{'CENTRALUPLOADDIR'};

print start_html('Abilene OWAMP mesh.'),
	h1('Abilene OWAMP mesh');

my $recv;

foreach my $mtype (@mtypes){
    my $first_row = [$mtype, @nodes];
    my $table_str = 
    q/print table({-border=>1},
		caption(''),
		Tr({-align=>'CENTER',-valign=>'TOP'},
		   [
		    th($first_row),/;
    foreach $recv (@nodes){
	my $rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	my @senders_data = map {fetch_sender_data($_, $recv)} @nodes;

#	print "\@sender_data is:\n";
#	print join " ", @senders_data, "\n";

	$table_str .= "td(['$recv ($rec_addr)', ";
	$table_str .= join(', ', @senders_data);
        $table_str .=  "]),\n";
	foreach my $sender (@nodes) {
	    ;
	}
    }

    $table_str .= q/]
		  )
	       )/;

#    print "\n\n", $table_str;
    eval $table_str;
}

print end_html;

die;

sub fetch_sender_data {
    my ($sender, $recv) = @_;
    return "'$recv/$sender'";
}
