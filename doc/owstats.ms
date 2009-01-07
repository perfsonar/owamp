'\"t
." The first line of this file must contain the '"[e][r][t][v] line
." to tell man to run the appropriate filter "t" for table.
." vim: set filetype=nroff :
."
."	$Id$
."
."######################################################################
."#									#
."#			   Copyright (C)  2004				#
."#	     			Internet2				#
."#			   All Rights Reserved				#
."#									#
."######################################################################
."
."	File:		owstats.man
."
."	Author:		Jeff Boote
."			Internet2
."
."	Date:		Wed Apr 28 08:48:05 MDT 2004
."
."	Description:	
."
.TH owstats 1 "$Date$"
.SH NAME
owstats \- Command line application used to parse \fBOWAMP\fR data files.
.SH SYNOPSIS
.B owstats 
[\fIoptions\fR] datafile.owp [datafile2.owp ...]
.SH DESCRIPTION
\fBowstats\fR is a command line application that is used to parse \fBOWAMP\fR
data files. It is used to display the results in a number of different
textual formats.
.so owping_report.man
.SH OPTIONS
.TP
\fB\-h\fR
.br
Print a usage message and exit.
.RS
.IP Default:
Unset.
.RE
.so owping_out_opts.man
.SH EXAMPLES
.LP
\fBowstats datafile.owp\fR
.IP
Report the summary statistics from the file datafile.owp.
.LP
\fBowstats -a 5,95 datafile.owp\fR
.IP
Report the summary statistics from the file datafile.owp. Also,
report the 5th and 95th percentile of delay as an extra statistics.
.LP
\fBowstats -R datafile.owp\fR
.IP
Print out the packets in a more machine readable format with no
statistics computed at all.
.LP
\fBowstats -v datafile.owp\fR
.IP
Show individual delays for each packet with summary statistics
printed at the end.
.LP
\fBowstats -M datafile.owp\fR
.IP
Print out summary statistics in a more computer pars-able format.
.LP
\fBowstats datafile1.owp datafile2.owp datafile3.owp\fR
.IP
Print out summary statistics for multiple files.
.SH SEE ALSO
owampd(8), owping(1), owfetch(1) and the \fBOWAMP\fR web site
\%(http://e2epi.internet2.edu/owamp/).
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
