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
 *	File:		conf.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Fri Feb 28 09:14:50 MST 2003
 *
 *	Description:	
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <owamp/owamp.h>
#include "conf.h"

/*
 * Function:	OWPDGetConfLine
 *
 * Description:	
 * 		Read a single line from a file fp. remove leading whitespace,
 * 		skip blank lines and comment lines. Put the result in the
 * 		char buffer pointed at by lbuf, growing it as necessary.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
int
OWPDGetConfLine(
	OWPContext	ctx,
	FILE		*fp,
	int		rc,
	char		**lbuf,
	size_t		*lbuf_max
	)
{
	int	c;
	char	*line = *lbuf;
	size_t	i=0;

	while((c = fgetc(fp)) != EOF){

		/*
		 * If c is a newline - increment the row-counter.
		 * If lbuf already has content - break out, otherwise
		 * this was a leading blank line, continue until there
		 * is content.
		 */
		if(c == '\n'){
			rc++;
			if(i) break;
			continue;
		}

		/*
		 * swallow comment lines
		 */
		if(!i && c == '#'){
			while((c = fgetc(fp)) != EOF){
				if(c == '\n'){
					rc++;
					break;
				}
			}
			continue;
		}

		/*
		 * swallow leading whitespace
		 */
		if(!i && isspace(c)){
			continue;
		}

		/*
		 * Check for line continuation.
		 */
		if(c == '\\'){
			if(fgetc(fp) == '\n'){
				rc++;
				continue;
			}
			OWPError(ctx,OWPErrFATAL,OWPErrINVALID,
					"Invalid use of \'\\\'");
			return -rc;
		}

		/*
		 * make sure lbuf is large enough for this content
		 */
		if(i+2 > *lbuf_max){
			*lbuf_max += OWPDLINEBUFINC;
			*lbuf = realloc(line,sizeof(char) * *lbuf_max);
			if(!*lbuf){
				if(line){
					free(line);
				}
				/*
				 * OWPError can't handle %M in the
				 * null context case - so use strerror
				 * directly.
				 */
				OWPError(ctx,OWPErrFATAL,errno,
						"realloc(%u): %s",*lbuf_max,
						strerror(errno));
				return -rc;
			}
			line = *lbuf;
		}

		/*
		 * copy char
		 */
		line[i++] = c;
	}

	line[i] = '\0';

	if(!i){
		return 0;
	}

	if(c == EOF){
		rc++;
	}

	return rc;
}

/*
 * Function:	OWPDReadConfVar
 *
 * Description:	
 * 	Read the next non-comment line from the config file. The file
 * 	should be in the format of:
 * 		key [value] [#blah comment]
 *
 * 	key and value are delineated by whitespace.  All leading and
 * 	trailing whitespace is ignored. A trailing comment is legal and
 * 	all charactors between a # and the trailing \n are ignored.
 *
 * In Args:	
 *
 * Out Args:	
 *
 * Scope:	
 * Returns:	
 * Side Effect:	
 */
int
OWPDReadConfVar(
	FILE	*fp,
	int	rc,
	char	*key,
	char	*val,
	size_t	max,
	char	**lbuf,
	size_t	*lbuf_max
	)
{
	char	*line;

	if((rc = OWPDGetConfLine(NULL,fp,rc,lbuf,lbuf_max)) > 0){

		/*
		 * Pull off key.
		 */
		if(!(line = strtok(*lbuf,OWPDWSPACESET))){
			rc = -rc;
			goto DONE;
		}

		/*
		 * Ensure key is not too long.
		 */
		if(strlen(line)+1 > max){
			rc = -rc;
			goto DONE;
		}
		strcpy(key,line);

		if((line = strtok(NULL,OWPDWSPACESET))){
			/*
			 * If there is no "value" for this key, then
			 * a comment is valid.
			 */
			if(*line == '#'){
				val[0] = '\0';
				goto DONE;
			}

			/*
			 * Ensure value is not too long.
			 */
			if(strlen(line)+1 > max){
				rc = -rc;
				goto DONE;
			}
			strcpy(val,line);
		}
		else{
			val[0] = '\0';
		}

		/*
		 * Ensure there is no trailing data
		 */
		if((line = strtok(NULL,OWPDWSPACESET))){
			/*
			 * Comments are the only valid token.
			 */
			if(*line != '#'){
				rc = -rc;
			}
		}
	}

DONE:
	return rc;
}
