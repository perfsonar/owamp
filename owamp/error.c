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

static void
OWPDefErrFunc(
	OWPErrSeverity		severity	__attribute__((unused)),
	OWPErrType		etype		__attribute__((unused)),
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
	char	buff[_OWP_ERR_MAXSTRING];

	vsnprintf(buff,sizeof(buff),fmt,args);
	if(!ctx || !ctx->cfg.err_func ||
		(*ctx->cfg.err_func)(ctx->cfg.app_data,severity,etype,buff))
		OWPDefErrFunc(severity,etype,buff);

	return;
}

void
OWPError(
	OWPContext	ctx,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*fmt,
	...
)
{
	va_list		args;

	if(!fmt)
		return;

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
	int		rc;
	char		buff[_OWP_ERR_MAXSTRING];

	rc = snprintf(buff,sizeof(buff),"%s(%d):",file,line);
	if(fmt)
		strncat(buff,fmt,sizeof(buff)-rc);

	va_start(args,fmt);
	_OWPError(ctx,severity,etype,buff,args);
	va_end(args);

	return;
}

OWPErrSeverity
_OWPFailControlSession(
	OWPControl	cntrl,
	OWPErrSeverity	err,
	OWPErrType	etype,
	char		*fmt,
	...
		)
{
	va_list		args;

	if(fmt){
		va_start(args,fmt);
		_OWPError(cntrl->ctx,err,etype,fmt,args);
		va_end(args);
	}

	cntrl->state = _OWPStateInvalid;

	return err;
}
