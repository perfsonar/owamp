#!/usr/local/bin/perl -w
#
#      $Id$

use strict;

# This script generates static html pages for all individual
# links in all active meshes.

# usage: pairs_pages_init.pl

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
my @resolutions = $conf->get_val(ATTR=>'DIGESTRESLIST');

my $fake_res = 30;
my $mode = 1;


foreach my $mtype (@mtypes) {
    foreach my $recv (@nodes) {
	foreach my $sender (@nodes) {
	    my ($rel_dir, $wwwdir, $rel_wwwdir);
	    (undef, undef, $wwwdir) =
		    $conf->get_names_info($mtype, $recv, $sender, $fake_res);

	    if (-f $wwwdir) {
		warn "$wwwdir exists and is a file - skipping";
	    }

	    unless (-d $wwwdir ) {
		mkpath([$wwwdir], 0, 0755) or
			die "Could not create dir $wwwdir: $!";
	    }
	    my $html_file = "$wwwdir/index.html";
	    open FH, ">$html_file"
		    or die "Could not open $html_file: $!";
	    select FH;
	    print start_html("$mtype mesh. Link $sender --> $recv");
#	    print '<META HTTP-EQUIV="refresh"; content="10;">';
	    print h1("$mtype mesh. Link $sender --> $recv"), "\n";
	    my $href1 = a({-href => '#delays'}, 'Delay statistics') . "\n";
	    my $href2 = a({-href => '#loss'}, 'Loss statistics') . "\n";
	    print ol(li($href1) . "\n", li($href2) . "\n"), "\n";

	    foreach my $type ('delays', 'loss') {
		print h2(a({-name=>"$type"}, upcase($type) . " statistics.")),
			"\n";
		foreach my $res (@resolutions) {
		    my $res_name = $conf->must_get_val(DIGESTRES=>$res,
						       ATTR=>'COMMONRESNAME');
		    my $period_name = $conf->must_get_val(DIGESTRES=>$res,
						     ATTR=>'PLOT_PERIOD_NAME');

		    my $png_name = $res;
		    my $title = "Sample period: $period_name. Frequency: " .
			    "$res_name";
		    print h4({-align=>'CENTER'}, $title), "\n";
		    print p({align => "CENTER"},
			    img {src => "$png_name-$type.png"}), "\n";
		}
	    }

	    print end_html;
	    close FH;
	}
    }
}

# convert a word to uppercase.
sub upcase {
    my $ret = $_[0];
    $ret =~ s/^(.*)$/\u$1/;
    return $ret;
}
