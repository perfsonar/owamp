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
#include <owampP.h>

static void
OWPDefErrFunc(
	OWPErrSeverity	severity,
	OWPErrType		etype,
	char			*buff
)
{
	fwrite(buff,sizeof(char),strlen(buff),stderr);
	fwrite("\n",sizeof(char),1,stderr);

	return;
}

static void
_OWPError(
	OWPContext		ctx,
	OWPErrSeverity	severity,
	OWPErrType		etype,
	const char		*fmt,
	va_list			args
)
{
	char	buff[OWP_ERR_MAXSTRING];

	vsnprintf(buff,sizeof(buff),fmt,args);
	if(!ctx || !ctx->cfg.errfunc ||
		(*ctx->cfg.errfunc)(ctx->cfg.app_data,severity,etype,buff))
		OWPDefErrFunc(severity,etype,buff);

	return;
}

void
OWPError(
	OWPContext		ctx,
	OWPErrSeverity	severity,
	OWPErrType		etype,
	const char		*fmt,
	...
)
{
	va_list		args;

	va_start(args,fmt);
	_OWPError(ctx,severity,etype,fmt,args);
	va_end(args);

	return;
}

void
OWPErrorLine(
	OWPContext		ctx,
	const char		*file,
	int			line,
	OWPErrSeverity	severity,
	OWPErrType		etype,
	const char		*fmt,
	...
)
{
	va_list		args;
	int		ret;
	char		buff[OWP_ERR_MAXSTRING];

	ret = snprintf(buff,sizeof(buff),"%s(%d):",file,line);
	strncat(buff,fmt,sizeof(buff-ret));

	va_start(args,fmt);
	_OWPError(ctx,severity,etype,buff,args);
	va_end(args);

	return;
}
