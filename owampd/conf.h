/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		conf.h
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Fri Feb 28 10:40:18 MST 2003
 *
 *	Description:	
 */
#ifndef	OWD_CONF_H
#define	OWD_CONF_H

#include <stdio.h>
#include <owamp/owamp.h>

/*
 * Growth increment for linebuffer.
 */
#define OWPDLINEBUFINC	120


/*
 * same charactors isspace checks for - useful for strtok splits
 * of whitespace.
 */
#define OWPDWSPACESET   "\t\n\v\f\r "

extern int
OWPDGetConfLine(
	OWPContext	ctx,
	FILE		*fp,
	int		rc,
	char		**lbuf,
	size_t		*lbuf_max
	);

extern int
OWPDReadConfVar(
	FILE	*fp,
	int	rc,
	char	*key,
	char	*val,
	size_t	max,
	char	**lbuf,
	size_t	*lbuf_max
	);

#endif	/* OWD_CONF_H */
