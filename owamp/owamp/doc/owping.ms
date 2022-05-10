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
.\"	File:		owping.1
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
.TH owping 1 "$Date$"
.SH NAME
owping \- Client application to request one-way latency tests.
.SH SYNOPSIS
.B owping 
[\fIoptions\fR] testpeer [server]
.SH DESCRIPTION
\fBowping\fR is a command line client application that is used to
initiate one-way latency tests.
.PP
Round-trip latency measurements (ping) are
an accepted technique to look for network problems; One-way measurements
have the potential to be even more useful. With round-trip measurements
it is difficult to isolate the direction in which congestion is experienced.
Traffic is often asymmetric with many sites being either primarily producers
or consumers of data. One-way measurements allow more informative
measurements. It is much easier to isolate the effects of traffic on
specific parts of a network.
.PP
.B owping
works by
contacting an \fBowampd\fR daemon on the remote peer host.
\fBowampd\fR manages the resources of the host on which it runs.
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
is an optional argument that indicates the \fBOWAMP\fR server address
if it is different from the \fItestpeer\fR. This is mostly useful in
the case of hosts with more than one network interface where the
\fBOWAMP\fR server is not listening on the interface that you want to test.
The \fIserver\fR can be specified using the same syntax as the \fItestpeer\fR.
\.
.PP
The \fBowping\fR client is used to request the type of
test wanted. The parameters allow the user to select the full send schedule,
direction of test (send, receive, or both) as well as packet size.
The results are returned to the client after the test completes. The
test will not be complete until \fItimeout\fR after the last packet is
scheduled to be sent.
.PP
With no options specified, \fBowping\fR will perform concurrent bidirectional
tests of 100 packets each at a rate of approximately 1 packet every 0.1
seconds to and from the \fItestpeer\fR. Then, the receivers on each host
will wait a reasonable period after that to count possible duplicate packets.
(See the \fI\-L\fR option.) Upon completion of the sessions, summary statistics
are printed to STDOUT.
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
\fBowping somehost.com\fR
.IP
Run two concurrent ~10-second test sessions at a rate of a packet every 0.1
seconds. One session sending packets from the local host to somehost.com,
the other session receiving packets from somehost.com. Print summary
statistics of the results only.
.LP
\fBowping somehost.com:98765
.IP
Run the same two concurrent test sessions to a server running on somehost.com
but on a non-default port.
.LP
\fBowping -u someuser somehost.com\fR
.IP
Run the default test as in the first example. Authenticate using
the identity \fIsomeuser\fR. \fBowping\fR will prompt for a \fIpassphrase\fR.
.LP
\fBowping -f somehost.com\fR
.IP
Run a single ~10-second test session at a rate of one packet every 0.1
seconds with the packets being sent from somehost.com and received
at the local host.
.LP
\fBowping -F from.owp somehost.com\fR
.IP
Same as the previous example, with the resulting data saved in
from.owp. The \fBowstats\fR program can be used to decode
that datafile using the same Output options that are available in
\fBowping\fR.
.LP
\fBowping -F from.owp -T to.owp somehost.com\fR
.IP
Run two concurrent ~10-second test sessions at a rate of a packet every 0.1
seconds. One session sending packets from the local host to somehost.com,
the other session receiving packets from somehost.com. Print summary
statistics of the results and save the resulting data saved in from.owp and
to.owp.
.LP
\fBowping -i 1e -c 10 somehost.com\fR
.IP
Run two concurrent ~10-second test sessions at an average rate of 1 packet
every second. One session sending packets from the local host to
somehost.com, the other session receiving packets from somehost.com.
Print summary statistics of the results only.
.LP
\fBowping -i 1f -c 10 somehost.com\fR
.IP
Run two concurrent ~10-second test sessions at a rate of 1 packet
every second. One session sending packets from the local host to
somehost.com, the other session receiving packets from somehost.com.
Print summary statistics of the results only.
.LP
\fBowping -i 1.0e,0f -c 20 somehost.com\fR
.IP
Run two concurrent ~10-second test sessions. Send back-to-back packet
pairs at an average rate of a packet pair every 1 seconds.
One session sending packets from the local host to
somehost.com, the other session receiving packets from somehost.com.
Print summary statistics of the results only.
.SH NOTES
Use of authentication and encryption modes adds extra processing
requirements between the fetching of a timestamp and when the packet
is sent, with it being greater for encryption than for
authentication. This adds more computational delay to the time
reported by \fBOWAMP\fR for each packet.
.SH SEE ALSO
owampd(8), owstats(1), owfetch(1) and the \%http://e2epi.internet2.edu/owamp/
web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
