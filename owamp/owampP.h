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
*/

/*
 * Data structures
 */
struct OWAMPConnectionRec{
	int	server;	/* connection represents server */
	int	state;	/* current state of connection */
};
