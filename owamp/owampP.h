/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*	     University Corporation for Advanced Internet Development	*
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
struct OWAMPConnectionRec{
	int			server;	/* connection represents server */
	int			state;	/* current state of connection */
	OWAMPSessionMode	mode;
};

struct OWAMPTestEndpointRec{
	OWAMPBoolean		endpoint_active;
	OWAMPBoolean		reciever;
	pid_t			chld;

	int			af;
	struct	in_addr		in_addr;
	struct	in6_addr	in6_addr;
	u_int16_t		port;

	OWAMPSID		sid;
	OWAMPTestSpec		test_spec;
};
