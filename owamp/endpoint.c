/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		endpoint.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Wed May 29 09:17:21 MDT 2002
 *
 *	Description:	
 *		This file contains the "default" implementation for
 *		the send and recv endpoints of an OWAMP test session.
 */
#include <unistd.h>
#include <netinet/in.h>
#include "owampP.h"
#include "endpoint.h"

/*
 * This type holds all the information needed for an endpoint to be
 * managed by these functions.
 */
typedef struct _DefEndpointRec{
	pid_t			child;
	OWPTestSpecPoisson	test_spec;
	OWPSID			sid;
	int			sockfd;
	int			filefd;
} _DefEndpointRec, *_DefEndpoint;

static _DefEndpoint
EndpointAlloc(
	OWPContext	ctx
	)
{
	_DefEndpoint	ep = malloc(sizeof(_DefEndpointRec));

	if(!ep){
		OWPError(ctx,OWPErrFATAL,errno,"malloc(DefEndpointRec)");
		return NULL;
	}

	ep->child = 0;
	ep->test_spec.test_type = OWPTestUnspecified;

	return ep;
}

/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
OWPErrSeverity
OWPDefEndpointInit(
	void		*app_data,
	void		**end_data_ret,
	OWPBoolean	send,
	OWPAddr		localaddr,
	OWPTestSpec	*test_spec,
	OWPSID		sid
)
{
	OWPContext		ctx = (OWPContext)app_data;
	struct sockaddr_in	*addr_in;
	struct sockaddr_in6	*addr_in6;
	_DefEndpoint		ep=EndpointAlloc(ctx);

	if(!ep)
		return OWPErrFATAL;

	/*
	 * TODO:socket/bind
	 * set fd in localaddr
	 * getsockname to get port number.
	 * set it in localaddr->saddr
	 */
	/*
	 * for now fake setting of port.
	 */
	if(localaddr->saddr->sa_family == AF_INET){
		addr_in = (struct sockaddr_in *)localaddr->saddr;
		addr_in->sin_port = htons(2222);
	}
	else if(localaddr->saddr->sa_family == AF_INET6){
		addr_in6 = (struct sockaddr_in6 *)localaddr->saddr;
		addr_in6->sin6_port = htons(2222);
	}
	else{
		OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
					"EndpointInit:Invalid address family");
		return OWPErrFATAL;
	}

	if(!send){
		int	i;
		/*
		 * set sid.
		 */
		for(i=0;i<16;i++) sid[i] = i;

		/*
		 * Open file for saving data.
		 */
	}

	*(_DefEndpoint*)end_data_ret = ep;

	return OWPErrOK;
}

/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
OWPErrSeverity
OWPDefEndpointInitHook(
	void		*app_data,
	void		*end_data,
	OWPAddr		remoteaddr,
	OWPSID		sid
)
{
	OWPContext		ctx = (OWPContext)app_data;
	struct sockaddr_in	*addr_in;
	struct sockaddr_in6	*addr_in6;
	_DefEndpoint		ep=(_DefEndpoint)end_data;

	memcpy(ep->sid,sid,sizeof(OWPSID));
	/*
	 * TODO:connect localaddr->fd to remote addr.
	 *
	 * fork child/ save pid for signals to "stop"
	 */

	return OWPErrOK;
}

OWPErrSeverity
OWPDefEndpointStart(
	void	*app_data,
	void	*end_data
	)
{
	return OWPErrOK;
}

OWPErrSeverity
OWPDefEndpointStop(
	void		*app_data,
	void		*end_data,
	OWPAcceptType	aval
	)
{
	return OWPErrOK;
}
