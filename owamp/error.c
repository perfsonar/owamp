/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
**	File:		error.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Fri Mar 29 15:36:44  2002
**
**	Description:	
*/
#include <stdio.h>
#include <stdarg.h>
#include <owampP.h>

void
OWPError_(
	OWPContext		ctx,
	OWPErrSeverity		severity,
	OWPErrType		etype,
	const char		*fmt,
	...
)
{
	va_list		ap;

	va_start(ap,fmt);

	if(ctx && ctx->eh){
		I2ErrLogVT(ctx->eh,(int)severity,etype,fmt,ap);
	}
	else{
		char		buff[_OWP_ERR_MAXSTRING];

		vsnprintf(buff,sizeof(buff),fmt,ap);
		fwrite(buff,sizeof(char),strlen(buff),stderr);
		fwrite("\n",sizeof(char),1,stderr);
	}
	va_end(ap);

	return;
}
