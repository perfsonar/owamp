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
 *	File:		util.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Tue Aug 06 14:46:15 MDT 2002
 *
 *	Description:	
 */
#include <ctype.h>
#include <owamp/owamp.h>

/*
 * buff must be at least (nbytes*2) +1 long or memory will be over-run.
 */
void
OWPHexEncode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	)
{
	char		hex[]="0123456789abcdef";
	unsigned int	i;

	for(i=0;i<nbytes;i++){
		*buff++ = hex[*bytes >> 4];
		*buff++ = hex[*bytes++ & 0x0f];
	}
	*buff = '\0';
}

void
OWPHexDecode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	)
{
	char		hex[]="0123456789abcdef";
	unsigned int	i,j,offset;
	char		a;

	for(i=0;i<nbytes;i++,bytes++){
		*bytes = 0;
		for(j=0;(*buff != '\0')&&(j<2);j++,buff++){
			a = tolower(*buff);
			for(offset=0;offset<sizeof(hex);offset++){
				if(a == hex[offset]){
					*bytes |= offset;
					if(!j)
						*bytes <<= 4;
					break;
				}
			}
		}
	}
}

