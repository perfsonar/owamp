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
#ifndef	OWAMPP_H
#define	OWAMPP_H
#include <owamp.h>

#define	OWP_ERR_MAXSTRING	1024

/*
 * Data structures
 */
typedef struct OWPContextRec OWPContextRec;
struct OWPContextRec{
	OWPInitializeConfigRec	cfg;
};

typedef struct OWPAddrRec OWPAddrRec;
struct OWPAddrRec{
	OWPContext	ctx;

	OWPBool		node_set;
	char		node[MAXHOSTNAMELEN+1];

	OWPBool		ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	OWPBool		fd_user;
	int		fd;
};

typedef struct OWPControlRec OWPControlRec;
struct OWPControlRec{
	OWPContext		ctx;

	int			server;	/* connection represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;

	OWPAddr			addr;

	struct OWPControlRec	*next;
};

struct OWPTestSessionRec{
	struct sockaddr			send_addr,
	struct sockaddr			recv_addr,
	struct OWPTestSessionRec	*next;
};

#endif	/* OWAMPP_H */
