/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		owampP.h
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Wed Mar 20 11:10:33  2002
**
**	Description:	
**	This header file describes the internal-private owamp API.
**
**	testing
*/

/*
 * Data structures
 */

struct OWAMPAddrRec{
	char			node[MAXHOSTNAMELEN];

	struct addrinfo		*ai;

	int			af;
	struct in_addr		v4addr;
	struct in6_addr		v6addr;
};

struct OWAMPControlConnectionRec{
	int			server;	/* connection represents server */
	int			state;	/* current state of connection */
	OWAMPSessionMode	mode;
};

struct OWAMPTestSessionRec{
	struct sockaddr			send_addr,
	struct sockaddr			recv_addr,
	struct OWAMPTestSessionRec	*next;
};
