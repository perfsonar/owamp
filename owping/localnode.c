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
 *	File:		localnode.c
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Tue Apr 30 10:27:16  2002
 *
 *	Description:	
 *
 * 		Find local addresses and put them in a hash.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "./localnode.h"

/*
 * Function:	is_local_node
 *
 * Description:	
 * 	Determine if the given nodename is a name for an interface on
 * 	this system.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
I2Boolean
is_local_node(
	const char	*nodename,
	int		socktype
	)
{
	struct addrinfo hints = {
		0,			/* ai_flags	*/
		PF_UNSPEC,		/* ai_family	*/
		socktype,		/* ai_socktype	*/
		0};
	struct addrinfo	*ai_ret = NULL, *ai = NULL;
	I2Boolean	val=False;


	if(socktype)
		ai = &hints;

	if( (getaddrinfo(nodename,NULL,ai,&ai_ret) != 0))
		return False;

	for(ai=ai_ret;ai && !val;ai=ai->ai_next){
		int	sockfd;

		sockfd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
		if(sockfd < 0)
			continue;

		if( (bind(sockfd,ai->ai_addr,ai->ai_addrlen) == 0)){
			val=True;
		}

		close(sockfd);
	}

	freeaddrinfo(ai_ret);

	return val;
}
