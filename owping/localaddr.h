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
 *	File:		localaddr.h
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
#ifndef	_localaddr_h_
#define	_localaddr_h_
#include <I2util/util.h>

extern I2Boolean
is_local_node(
	const char	*nodename
	);

#endif	/* _localaddr_h_ */
