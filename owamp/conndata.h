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
 *	File:		conndata.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Thu Jul 04 10:24:44 MDT 2002
 *
 *	Description:	
 *			This file declares the datatype used by the
 *			default connection related functions to maintain
 *			state. (pipefd to parent process for requesting
 *			resources, and holds paths etc. to determine
 *			where to store session files.)
 */
#ifndef	_OWP_CONNDATA_H
#define	_OWP_CONNDATA_H

#include <owpcontrib/access.h>

typedef struct OWPPerConnDataRec{
	int	          pipefd;		/* pipe to parent	*/

	char	          *session_data_path;
	policy_data       *policy;              /* global policy hash */
	owp_tree_node_ptr node;                 /* node for the connection
						   class */
} OWPPerConnDataRec, *OWPPerConnData;

#endif	/*	_OWP_CONNDATA_H	*/
