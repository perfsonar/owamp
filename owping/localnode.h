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
 *	File:		localnode.h
 *
 *	Author:		Jeff Boote
 *			Internet2
 *
 *	Date:		Tue Apr 30 10:31:24  2002
 *
 *	Description:	
 *
 * 		Find local addresses and put them in a hash.
 */
#ifndef	_localnode_h_
#define	_localnode_h_
#include <I2util/util.h>

extern I2Boolean
is_local_node(
	const char	*nodename,
	int		socktype
	);

#endif	/* _localnode_h_ */
