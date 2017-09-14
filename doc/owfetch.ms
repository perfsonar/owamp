'\"t
.\" The first line of this file must contain the '"[e][r][t][v] line
.\" to tell man to run the appropriate filter "t" for table.
.\" vim: set filetype=nroff :
.\"
.\"	$Id$
.\"
.\"######################################################################
.\"#									#
.\"#			   Copyright (C)  2004				#
.\"#	     			Internet2				#
.\"#			   All Rights Reserved				#
.\"#									#
.\"######################################################################
.\"
.\"	File:		owfetch.1
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Wed Apr 28 08:48:05 MDT 2004
.\"
.\"	Description:	
.\"
.\"Protocol name
.ds proto OWAMP
.TH owfetch 1 "$Date$"
.SH NAME
owfetch \- Client application to fetch buffered \fBOWAMP\fR session data.
.SH SYNOPSIS
.B owfetch
[\fIoptions\fR] servhost [SID savefile]+
.SH DESCRIPTION
\fBowfetch\fR is a command line client application used to
fetch buffered \fBOWAMP\fR session data.
.PP
\fBOWAMP\fR one-way latency measurements send packets from a sending host
to a receiving host. The receiving host is the only entity that ends up
with the results of the test. When
the \fBowampd\fR daemon is used to setup a receiving endpoint, the daemon
buffers that data. The owfetch application can be used to \fIfetch\fR the
buffered data. (\fBowping\fR typically retrieves this information immediately
upon completion of the test making this unnecessary in most cases.)
.PP
\fBowfetch\fR is a simple application that can be used to fetch this
buffered data from a \fBowampd\fR process running on \fIservhost\fR
if it was not saved as part of the \fBowping\fR execution.
.PP
.I servhost
can be specified using rfc2396 and rfc2732 syntax for both host and
port specification:
.TP
.I node:port
.br
IPv4 syntax where node is either a DNS name or a numeric host address string
consisting of a dotted decimal IPv4 address. The \fI\:port\fR is an optional
port specifier to contact servers running on a non-default port and
can be left off in most cases.
This syntax also works for IPv6 addresses specified using DNS names.
.TP
.I [node]:port
IPv6 syntax where node is specified using a numeric IPv6 host address
string. The []'s are required only if the optional \fI\:port\fR port
specifier is used.
.PP
The \fISID\fR (Session Identifier) is a hex number that uniquely identifies
a single test session. \fIsavefile\fR is the file in which the data from
that test session will be saved. Any number of \fISID\fR \fIsavefile\fR pairs
can be specified on the command-line to download more than one session per
command execution. The \fISID\fR is printed out when a test session is
requested by \fBowping\fR, unless output is suppressed with the \fI\-Q\fR
option.
.PP
\fIsavefile\fR can be specified as /dev/null on UNIX if there is no desire
to actually save the session data.
.PP
If no options are specified, \fBowfetch\fR retrieves the buffered session
data from \fIservhost\fR, saves the data to the \fIsavefile\fR,
and prints summary statistics.
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
.so owping_conn_opts.man
.so owping_out_opts.man
.SH EXAMPLES
.LP
\fBowfetch somehost.com abcdef0123456789abcdef0123456789 save.owp\fR
.IP
Contact host somehost.com. Fetch the test session identified by
the SID abcdef0123456789abcdef0123456789. Print summary statistics on that
file and save the data in save.owp.
.LP
\fBowfetch -R somehost.com abcdef0123456789abcdef0123456789 save.owp\fR
.IP
Contact host somehost.com. Fetch the test session identified by
the SID abcdef0123456789abcdef0123456789. Print the raw decoding of the
data in that file and save the session data in save.owp.
.LP
\fBowfetch -M somehost.com abcdef0123456789abcdef0123456789 save.owp\fR
.IP
Contact host somehost.com. Fetch the test session identified by
the SID abcdef0123456789abcdef0123456789. Print the machine pars-able
summary statistics for that session and save the session data in save.owp.
.LP
\fBowfetch -v somehost.com abcdef0123456789abcdef0123456789 save.owp\fR
.IP
Contact host somehost.com. Fetch the test session identified by
the SID abcdef0123456789abcdef0123456789. Print individual delays for each
packet in human readable format. Print the summary statistics.  Save the
session data in save.owp.
.LP
\fBowfetch -U someuser somehost.com abcdef0123456789abcdef0123456789 save.owp\fR
.IP
The same action as the first example.  Authenticate using
the identity \fIsomeuser\fR. \fBowfetch\fR will prompt for a \fIpassphrase\fR.
.SH SEE ALSO
owampd(8), owping(1), owstats(1), aespasswd(1) and
the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
