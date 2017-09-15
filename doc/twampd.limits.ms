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
.\"	File:		twampd.limits.ms
.\"
.\"	Author:		Jeff Boote
.\"			Internet2
.\"
.\"	Date:		Wed May 12 10:45:09 MDT 2004
.\"
.\"	Description:	
.\"
.\"Program name
.ds prog twampd
.TH twampd.limits 5
.SH NAME
twampd.limits \- Two-way active measurement server policy configuration file
.so nwampd_limits_desc.man
.SH EXAMPLES
An initial \fIlimit\fR line might look like:
.RS
.HP
limit root with \\
.br
bandwidth=900m, \\
.br
allow_open_mode=off
.RE
.PP
This would create a \fIlimitclass\fR named \fBroot\fR. Because no
\fIparent\fR is
specified, this must be the first \fIlimitclass\fR defined in the
file. This \fIlimitclass\fR has a very liberal limit for bandwidth
(900m). However, open mode authentication is not enabled for this
\fIlimitclass\fR, so the connections that get these limits must
successfully authenticate using an AES key derived from the
pass-phrase in the \fBtwampd.pfs\fR file.
.PP
If an administrator also wants to create a \fIlimitclass\fR that is used
to deny all requests, they might add:
.RS
.HP
limit jail with \\
.br
parent=root, \\
.br
bandwidth=1, \\
.br
allow_open_mode=off
.RE
.PP
This would create a \fIlimitclass\fR named \fBjail\fR. Because the
limit for bandwidth is so low, virtually all tests will be denied.
\fIallow_open_mode\fR is off, so initial connections that are not in
authenticated or encrypted mode will be dropped immediately.
(It would not make much sense to assign a \fIuser\fR identity to this
\fIlimitclass\fR. If you don't want connections from a particular \fIuser\fR
identity the best thing to do is to remove that \fIuser\fR from
the \fBtwampd.pfs\fR file.)
.PP
If the administrator wanted to allow a limited amount of open tests, they
could define a \fIlimitclass\fR like:
.RS
.HP
limit open with \\
.br
parent=root, \\
.br
bandwidth=10k, \\
.br
allow_open_mode=on
.RE
.PP
This could be used to allow testing by random connections.
It limits those tests to 10 kilobits of bandwidth.
.PP
Now, these three \fIlimitclasses\fR might be assigned to specific connections
in the following ways:
.RS
.PP
# default open
.br
assign default \fBopen\fR
.PP
# badguys subnet
.br
assign net 192.168.1.0/24 \fBjail\fR
.PP
# network admins
.br
assign user joe \fBroot\fR
.br
assign user jim \fBroot\fR
.br
assign user bob \fBroot\fR
.br
.RE
.PP
This set of \fIassign\fR lines specifically denies access from any
open mode connection from the \fBbadguys\fR subnet. It specifically
allows access to authenticated or encrypted mode transactions that can
authenticate as the \fIidentities\fR \fBjoe jim\fR or \fBbob\fR (even from
the \fBbadguys\fR subnet). All other connections would match the
\fIassign default\fR rule and get the limits associated with the \fBopen\fR
\fIlimitclass\fR.
.SH SEE ALSO
twping(1), twampd(8), twampd.limits(5), twampd.pfs(5), pfstore(1),
and the \%http://e2epi.internet2.edu/owamp/ web site.
.SH ACKNOWLEDGMENTS
This material is based in part on work supported by the National Science
Foundation (NSF) under Grant No. ANI-0314723. Any opinions, findings and
conclusions or recommendations expressed in this material are those of
the author(s) and do not necessarily reflect the views of the NSF.
