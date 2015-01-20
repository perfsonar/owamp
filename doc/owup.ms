'\"t
.\" The first line of this file must contain the '"[e][r][t][v] line
.\" to tell man to run the appropriate filter "t" for table.
.\" vim: set filetype=nroff :
.\"
.\"	$Id$
.\"
.\"######################################################################
.\"#									#
.\"#			   Copyright (C)  2006				#
.\"#	     			Internet2				#
.\"#			   All Rights Reserved				#
.\"#									#
.\"######################################################################
.\"
.\"	File:		owup.1
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Thu May 11 17:25:22 MDT 2006
.\"
.\"	Description:	
.\"
.\"Protocol name
.ds proto OWAMP
.TH owup 1 "$Date$"
.SH NAME
owup \- Client application to query the server for uptime information
.SH SYNOPSIS
.B owup
[\fIoptions\fR] servhost
.SH DESCRIPTION
\fBowup\fR is a command line client application used to
fetch uptime information from the server. The \fBowampd\fR greeting
message provides uptime information. This can be useful information
for clients that run long-duration test and for monitoring purposes.
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
.SH EXAMPLES
.LP
\fBowup somehost.com
.IP
Contact host somehost.com. Fetch the uptime information and display it.
.SH SEE ALSO
owampd(8), owping(1), owstats(1), aespasswd(1) and
the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
