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

foreach my $mtype (@mtypes) {
    foreach my $recv (@nodes) {
	foreach my $sender (@nodes) {
	    foreach my $res (@resolutions) {
		my ($rel_wwwdir, $link_html, $wwwdir);
		(undef, $wwwdir, undef, undef, $link_html) =
			$conf->get_names_info($mtype, $recv, $sender, $res, 1);
		$wwwdir = $conf->get_www_path($rel_wwwdir);

		if (-f $wwwdir) {
		    warn "$wwwdir exists and is a file - skipping"
		}

		unless (-d $wwwdir ) {
		    mkpath([$wwwdir], 0, 0755) or
			    die "Could not create dir $wwwdir: $!";
		}
		my $html_file = "$wwwdir/$link_html";
		open FH, ">$html_file"
			or die "Could not open $html_file: $!";
		print FH start_html("$mtype mesh. Link $sender --> $recv");
		print FH h1("$mtype mesh. Link $sender --> $recv");
		print FH end_html;
		close FH;
	    }
	}
    }
}

