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
 *	File:		localaddr.c
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
#include <unistd.h>

#include "./localaddr.h"

I2table
load_local_addrs(
	void
	)
{
	return NULL;
}

I2Boolean
is_local_addr(
	I2table		addrtable,
	char		*nodename
	)
{
	return False;
}

void
free_local_addrs(
	I2table		addrtable
	)
{
	return;
}
