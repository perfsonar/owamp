#!/usr/local/bin/perl -w
#
#      $Id$

use strict;

# This script generates top-level html page for all active meshes.

# usage: make_top_html.pl

use constant DEBUG => 1;
use constant VERBOSE => 1;

use FindBin;
use lib ("$FindBin::Bin");
use File::Path;
use CGI qw/:standard/;
use OWP;

$| = 1;

my $conf = new OWP::Conf(CONFDIR => "$FindBin::Bin");
my @mtypes = $conf->get_val(ATTR=>'MESHTYPES');
my @nodes = $conf->get_val(ATTR=>'MESHNODES');
# my $wwwdir = $conf->get_www_path("");
my $index_page = join '/', $conf->{'CENTRALWWWDIR'}, 'index.html';

my $recv;

open INDEXFH, ">$index_page" or die "Could not open $index_page";

print INDEXFH start_html('Abilene OWAMP actives meshes.'),
	h1('Abilene OWAMP active meshes.');

foreach my $mtype (@mtypes){
    my $first_row = [$mtype, @nodes];
    my $table_str =
    q/print INDEXFH table({-border=>1},
		caption(''),
		Tr({-align=>'CENTER',-valign=>'TOP'},
		   [
		    th($first_row),/;
    foreach $recv (@nodes){
	my $rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	my @senders_data = map {fetch_sender_data($_, $recv, $mtype)} @nodes;

	$table_str .= "td(['$recv ($rec_addr)', ";
	$table_str .= join(', ', @senders_data);
        $table_str .=  "]),\n";
    }

    $table_str .= q/]
		  )
	       )/;

    eval $table_str;
}

print INDEXFH end_html;
close INDEXFH;

sub fetch_sender_data {
    my ($sender, $recv, $mtype) = @_;

    my ($datadir, $rel_wwwdir, $summary_file, $png_file, $wwwdir) =
	    $conf->get_names_info($mtype, $recv, $sender, 30, 2);

    unless (-f $summary_file) {
	warn "summary file $summary_file not found - skipping";
	return "'N/A'";
    }

    open FH, "<$summary_file" or die "Could not open $summary_file: $!";
    my $line = <FH>;
    close FH;

    chomp $line;

    my ($median, $med, $ninety_perc) = split / /, $line;

    # create a proper link here
   return "'" . a({href => $rel_wwwdir}, $median) . "'";
}
