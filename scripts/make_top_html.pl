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

my $del_thresh = 100; # ms
my $loss_thresh = 1;  # % loss

my $recv;

open INDEXFH, ">$index_page" or die "Could not open $index_page";
select INDEXFH;

print  start_html('Abilene OWAMP active meshes.'),
	h1('Abilene OWAMP active meshes.');

print "\n<p>\n";
print <<"STOP";
Each mesh (IPv4, IPv6) is described by a separate table. For each
link within a mesh we print median delay (ms) and loss percentage.
Senders are listed going down the column, and receivers along the row.
Cells with delay of more than $del_thresh ms, or loss of more than
$loss_thresh\%, are marked in red.
STOP
print '</p>';

foreach my $mtype (@mtypes){
    my $first_row = join '', map {th($_)} $mtype, @nodes;
    print <<"STOP";
<table border=1>
<tr align="CENTER" valign="TOP">
$first_row
</tr>
STOP

    foreach $recv (@nodes){
	my $rec_addr = $conf->get_val(NODE=>$recv, TYPE=>$mtype, ATTR=>'ADDR');
	next unless defined $rec_addr;
	my @senders_data = map {fetch_sender_data($_, $recv, $mtype)} @nodes;

	print <<"STOP";
<tr align="CENTER" valign="TOP">
<td>$recv ($rec_addr)</td>
STOP

	# This can be customized to allowe for selective coloring of links.
	my $red = 0;

	foreach my $send_datum (@senders_data) {
#	    warn "$send_datum";
	    my ($datum, $median, $loss) = split /,/, $send_datum;
	    my $td = (($median > $del_thresh) || ($loss > $loss_thresh))?
		    'td bgcolor="red"' : 'td';
	    print "<$td>$datum</td>\n";
	}
	print "</tr>\n";
    }
print "</table>\n";
}

print end_html;
close INDEXFH;

sub fetch_sender_data {
    my ($sender, $recv, $mtype) = @_;

    my ($datadir, $summary_file, $wwwdir) =
	    $conf->get_names_info($mtype, $recv, $sender, 30, 2);

    my $rel_wwwdir = $conf->get_rel_path($mtype, $recv, $sender);

    unless (-f $summary_file) {
	warn "summary file $summary_file not found - skipping";
	return join ',', "N/A", "0", "0";
    }

    open FH, "<$summary_file" or die "Could not open $summary_file: $!";
    my $line = <FH>;
    close FH;

    chomp $line;

    my ($median, $med, $ninety_perc, $loss) = split / /, $line, 4;

    # create a proper link here
    my $tentry = "\n";
    $tentry .= a({href => "$rel_wwwdir/index.html#delays"}, $median);
    $tentry .= " / \n" ;
    $tentry .= a({href => "$rel_wwwdir/index.html#loss"}, "$loss%");
    $tentry .= "\n";
    return join ',', $tentry, $median, $loss;
}
