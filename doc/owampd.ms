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
.\"	File:		owampd.8
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Fri May  7 15:24:16 MDT 2004
.\"
.\"	Description:	
.\"
.de TQ
.br
.ns
.TP \\$1
..
.\"Program name
.ds prog owampd
.\"Protocol name
.ds proto OWAMP
.\"Port number
.ds port 861
.TH owampd 8 "$Date$"
.SH NAME
owampd \- One-way latency server.
.SH SYNOPSIS
.B owampd
[\fIoptions\fR]
.SH DESCRIPTION
.B owampd
is a server program specifically designed to run one side of one-way
latency tests. The client program \fBowping\fR is available to run
the other side of the test.
.PP
Aside from actually running the tests, the main function of \fBowampd\fR
is to determine which tests are allowed, based upon the policy restrictions
configured by the system administrator.
.PP
\fBowampd\fR was designed to be run as a stand-alone daemon process. It
uses the classic accept/fork model of handling new requests.
.PP
Most of the command line options for \fBowampd\fR have analogous options
in the \fBowampd.conf\fR file. The command line takes precedence.
.SH OPTIONS
.TP
.so nwampd_opts.man
.SH REQUIREMENTS
The \fBowampd\fR daemon requires a very well synchronized and stable clock.
\fBowampd\fR requires that \fBNTP\fR be running to synchronize
the system clock. \fBNTP\fR needs to be setup in a more methodical way
than on most systems for the results to be meaningful. Please see the
\fBOWAMP\fR web site \%(http://e2epi.internet2.edu/owamp/) for details
concerning proper configuration of \fBNTP\fR for \fBOWAMP\fR.
.SH ERRORS
\fBowampd\fR uses \fBsyslog\fR to output error messages including access
information. The \fIfacility\fR configuration option is used to determine
what \fBsyslog\fR facility is used. The levels used are as follows:
.IP \fBLOG_ERR\fR
Used for messages indicating fatal errors. The requested action will not
be performed.
.IP \fBLOG_WARNING\fR
Used for messages indicating an unexpected or dangerous condition.
.IP \fBLOG_INFO\fR
Used for access messages.
.IP \fBLOG_DEBUG\fR
Used to indicate reasons for actions. For example, if an access is denied
due to policy choices that will be noted with this log level.
.PP
These levels were chosen to give the system-administrator the ability to
separate access log information from error log information in a straight
forward manner.
.SH SIGNALS
.
The \fBowampd\fR process makes use of a number of signals to perform
IPC between the various processes involved:
.TP
\fBSIGALRM\fR
Used throughout to set timers where appropriate.
.TP
\fBSIGCHLD\fR
Used to keep track of the state of child processes.
.TP
.B SIGINT
.TQ
.B SIGTERM
.TQ
.B SIGHUP
Used to terminate any \fBowampd\fR process. These signals are caught by the
parent daemon and it manages the complete shutdown of all the \fBowampd\fR
processes.
.TP
\fBSIGPIPE\fR
Disabled throughout \fBowampd\fR.
.TP
\fBSIGUSR1\fR
Used to tell a spawned off receiver/sender process that all control
setup interaction is complete and the test can continue at the
determined time. (This is an indication that the StartSessions message
was received for those familiar with the \fBOWAMP\fR protocol.)
.TP
\fBSIGUSR2\fR
Used to tell a spawned off receiver/sender process to terminate a session
early. (This is an indication that a StopSessions message was received
for those familiar with the \fBOWAMP\fR protocol.)
.SH FILES
owampd.pid
.br
owampd.conf
.br
owampd.limits
.br
owampd.pfs
.SH ENVIRONMENT VARIABLES
\fBOWAMP\fR uses environment variables for some debugging options.
.TS
lb lb
_ _
lb li .
OWAMP Environment Variable	Description

OWAMP_DEBUG_TIMEOFFSET	Offset time by this amount (seconds)
.TE
.SH SEE ALSO
There are more details on configuring the \fBowampd\fR daemon in the
owampd.conf(5) manual page. Details on configuring the policy
are in the owampd.limits(5) and owampd.pfs(5) manual pages.
Information on the client is in the owping(1) manual page.
For more of an overview of the full functionality and architecture, see
the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
