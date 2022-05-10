'\"t
.\" The first line of this file must contain the '"[e][r][t][v] line
.\" to tell man to run the appropriate filter "t" for table.
.\" vim: set filetype=nroff :
.\"
.\"######################################################################
.\"#									#
.\"#			   Copyright (C)  2004				#
.\"#	     			Internet2				#
.\"#			   All Rights Reserved				#
.\"#									#
.\"######################################################################
.\"
.\"	File:		twping.1
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Wed Apr 28 08:48:05 MDT 2004
.\"
.\"	Description:	
.\"
.\"Protocol name
.ds proto TWAMP
.TH twping 1
.SH NAME
twping \- Client application to request two-way latency tests.
.SH SYNOPSIS
.B twping 
[\fIoptions\fR] testpeer [server]
.SH DESCRIPTION
\fBtwping\fR is a command line client application that is used to
initiate two-way latency tests.
.PP
Round-trip latency measurements using ping are an accepted technique
to look for network problems primarily because the local and remote
clocks do not need to be synchronised and no storage or much logic is
need on the reflector. However, such a technique suffers from the
problem of inaccurate results due to processing delays on the
reflector. One-Way measurements require that the local and remote
clocks be synchronised for accurate results. The \fBTWAMP\fR protocol
allows informative measurements without this requirement and it is
much easier to isolate the effects of traffic on specific parts of a
network compared to ping.
.PP
.B twping
works by
contacting a \fBTWAMP\fR server and reflector on the remote peer host.
.PP
.I testpeer
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
.I server
is an optional argument that indicates the \fBTWAMP\fR server address
if it is different from the \fItestpeer\fR. This is mostly useful in
the case of hosts with more than one network interface where the
\fBTWAMP\fR server is not listening on the interface that you want to test.
The \fIserver\fR can be specified using the same syntax as the \fItestpeer\fR.
\.
.PP
The \fBtwping\fR client is used to request the type of
test wanted. The parameters allow the user to select the full send schedule,
as well as packet size.
.PP
With no options specified, \fBtwping\fR will perform tests of 100
packets each at a rate of approximately 1 packet every 0.1 seconds to
and reflected from the \fItestpeer\fR. Then, the receiver will wait a
reasonable period after that to count possible duplicate packets.
(See the \fI\-L\fR option.) Upon completion of the sessions, summary
statistics are printed to STDOUT.
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
.so owping_test_opts.man
.so owping_conn_opts.man
.so owping_out_opts.man
.SH ENVIRONMENT VARIABLES
.TS
lb lb
_ _
lb li .
OWAMP Environment Variable	Description

OWAMP_DEBUG_TIMEOFFSET	Offset time by this amount (float)
.TE
.SH EXAMPLES
.LP
\fBtwping somehost.com\fR
.IP
Run two concurrent ~10-second test sessions at a rate of a packet every 0.1
seconds. One session sending packets from the local host to somehost.com,
the other session receiving packets from somehost.com.) Print summary
statistics of the results only.
.LP
\fBtwping somehost.com:98765
.IP
Run the same two concurrent test sessions to a server running on somehost.com
but on a non-default port.
.LP
\fBtwping -u someuser somehost.com\fR
.IP
Run the default test as in the first example. Authenticate using
the identity \fIsomeuser\fR. \fBtwping\fR will prompt for a \fIpassphrase\fR.
.LP
\fBtwping -F from.twp somehost.com\fR
.IP
Same as the previous example, with the resulting data saved in
\fIfrom.twp\fR. The \fBowstats\fR program can be used to decode
that datafile using the same Output options that are available in
\fBowping\fR.
.LP
\fBtwping -i 1e -c 10 somehost.com\fR
.IP
Run a ~10-second test session at an average rate of 1 packet every
second. Send packets, which are reflected by somehost.com, and then
received.  Print summary statistics of the results only.
.LP
\fBtwping -i 1f -c 10 somehost.com\fR
.IP
Run a ~10-second test session at a rate of 1 packet every second. Send
packets, which are reflected by somehost.com, and then received.
Print summary statistics of the results only.
.LP
\fBtwping -i 1.0e,0f -c 20 somehost.com\fR
.IP
Run a ~10-second test session. Send back-to-back packet
pairs at an average rate of a packet pair every 1 seconds.
Send packets, which are reflected by somehost.com, and then received.
Print summary statistics of the results only.
.SH SEE ALSO
twampd(8), owstats(1), and the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
