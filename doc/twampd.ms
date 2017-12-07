.\" The first line of this file must contain the '"[e][r][t][v] line
.\" to tell man to run the appropriate filter "t" for table.
.\" vim: set filetype=nroff :
.\"
.\"######################################################################
.\"#									#
.\"#			   Copyright (C)  2015				#
.\"#	     		Brocade Communications				#
.\"#			   All Rights Reserved				#
.\"#									#
.\"######################################################################
.\"
.\"	File:		twampd.8
.\"
.\"	Author:		Robert Shearman
.\"			Brocade Communications
.\"
.\"	Date:		Fri May  7 15:24:16 MDT 2004
.\"
.\"	Description:	
.\"       Based on owampd.ms
.\"
.de TQ
.br
.ns
.TP \\$1
..
.\"Program name
.ds prog twampd
.\"Protocol name
.ds proto TWAMP
.\"Port number
.ds port 862
.TH twampd 8
.SH NAME
twampd \- Two-way active measurement server.
.SH SYNOPSIS
.B twampd
[\fIoptions\fR]
.SH DESCRIPTION
.B twampd
is a server program that allows a client to perform two-way or
round-trip latency measurements. The application of timestamps in the
reflector enables greater accuracy over the other most common facility
for round-trip measurements, \fIICMP Echo Request/Reply\fR.
.PP
Aside from running the tests, the main function of \fBtwampd\fR
is to determine which tests are allowed, based upon the policy restrictions
configured by the system administrator.
.PP
\fBtwampd\fR was designed to be run as a stand-alone daemon process. It
uses the classic accept/fork model of handling new requests.
.PP
Most of the command line options for \fBtwampd\fR have analogous options
in the \fBtwampd.conf\fR file. The command line takes precedence.
.SH OPTIONS
.TP
.so nwampd_opts.man
.SH REQUIREMENTS
Unlike \fBOWAMP\fR, the \fBTWAMP\fR protocol does not require a well
synchronized clock. However, the clock should be stable.
.SH ERRORS
\fBtwampd\fR uses \fBsyslog\fR to output error messages including access
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
The \fBtwampd\fR process makes use of a number of signals to perform
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
Used to terminate any \fBtwampd\fR process. These signals are caught by the
parent daemon and it manages the complete shutdown of all the \fBtwampd\fR
processes.
.TP
\fBSIGPIPE\fR
Disabled throughout \fBtwampd\fR.
.TP
\fBSIGUSR1\fR
Used to tell a spawned off receiver/sender process that all control
setup interaction is complete and the test can continue at the
determined time. (This is an indication that the StartSessions message
was received for those familiar with the \fBTWAMP\fR protocol.)
.TP
\fBSIGUSR2\fR
Used to tell a spawned off receiver/sender process to terminate a session
early. (This is an indication that a StopSessions message was received
for those familiar with the \fBTWAMP\fR protocol.)
.SH FILES
twampd.pid
.br
twampd.conf
.br
twampd.limits
.br
twampd.pfs
.SH ENVIRONMENT VARIABLES
\fBtwampd\fR uses environment variables for some debugging options.
.TS
lb lb
_ _
lb li .
Environment Variable	Description

OWAMP_DEBUG_TIMEOFFSET	Offset time by this amount (seconds)
.TE
.SH SEE ALSO
There are more details on configuring the \fBtwampd\fR daemon in the
twampd.conf(5) manual page. Details on configuring the policy
are in the twampd.limits(5) and twampd.pfs(5) manual pages.
Information on the client is in the twping(1) manual page.
For more of an overview of the full functionality and architecture, see
the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
