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

foreach my $mtype (@mtypes) {
    foreach my $recv (@nodes) {
	foreach my $sender (@nodes) {
	    my ($rel_dir, $wwwdir, $rel_wwwdir);
	    (undef, $rel_dir, undef, undef, $wwwdir) =
		    $conf->get_names_info($mtype, $recv, $sender,
					  $fake_res, 1);

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
	    print h1("$mtype mesh. Link $sender --> $recv");
	    my $href1 = a({-href => '#delays'}, 'Delay statistics');
	    my $href2 = a({-href => '#loss'}, 'Loss statistics');
	    print ol(li($href1), li($href2));

	    foreach my $res (@resolutions) {
		my $res_name = $conf->must_get_val(DIGESTRES=>$res,
						   ATTR=>'COMMONRESNAME');
		my $period_name = $conf->must_get_val(DIGESTRES=>$res,
				      ATTR=>'PLOT_PERIOD_NAME');

		    my $title = "Sample period: $period_name. Frequency: " .
				    "$res_name";
		    print h4({-align=>'CENTER'}, $title);
		    print p({align => "CENTER"},
			    img {src => "$res.png"});
		    warn "DEBUG: src=$rel_dir/$res.png" if DEBUG;
	    }

	    print end_html;
	    close FH;
	}
    }
}
