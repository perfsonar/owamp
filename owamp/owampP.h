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

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#include "config.h"

#if	!HAVE_ERRNO_H || !HAVE_NETDB_H || !HAVE_STDLIB_H || !HAVE_SYS_PARAM_H
#error	Missing Header!
#endif

#if	!HAVE_GETADDRINFO || !HAVE_SOCKET
#error	Missing networking capabilities!
#endif

#if	!HAVE_MALLOC || !HAVE_MEMSET
#error	Missing needed functions!
#endif
#endif	/* HAVE_CONFIG_H */

#include <owamp.h>

#define	_OWP_ERR_MAXSTRING	1024
#define	_OWP_DO_ENCRYPT		(OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

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

	OWPBoolean	node_set;
	char		node[MAXHOSTNAMELEN+1];

	OWPBoolean	ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	OWPBoolean	saddr_set;
	struct sockaddr	saddr;

	OWPBoolean	fd_user;
	int		fd;
};

typedef struct OWPControlRec OWPControlRec;
struct OWPControlRec{
	OWPContext		ctx;

	int			server;	/* this record represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;
	OWPKID			kid;
	OWPKey			key;
	u_int32_t		challenge[4];

	OWPAddr			remote_addr;
	OWPAddr			local_addr;

	u_int32_t		session_key[4];
	u_int32_t		client_IV[4];

	struct OWPControlRec	*next;
};

struct OWPTestSessionRec{
	struct sockaddr			send_addr;
	struct sockaddr			recv_addr;
	struct OWPTestSessionRec	*next;
};

#endif	/* OWAMPP_H */
