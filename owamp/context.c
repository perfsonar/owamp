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
**	File:		context.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Fri Apr 12 09:11:31  2002
**
**	Description:	
*/
#include <owampP.h>

/*
 * Function:	_OWPCallGetAESKey
 *
 * Description:
 * 	Calls the get_key function that is defined by the application.
 * 	If the application didn't define the get_key function, then provide
 * 	the default response of False.
 */
OWPBoolean
_OWPCallGetAESKey(
	OWPContext	ctx,		/* library context	*/
	const char	*kid,		/* identifies key	*/
	OWPByte		*key_ret,	/* key - return		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
)
{
	*err_ret = OWPErrOK;

	if(!ctx){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
					"_OWPCallGetAESKey:No Context!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is no encryption support.
	 */
	if(!ctx->cfg.get_aes_key_func)
		return False;

	return (*ctx->cfg.get_aes_key_func)(ctx->cfg.app_data,kid,key_ret,err_ret);
}

/*
 * Function:	_OWPCallCheckAddrPolicy
 *
 * Description:
 * 	Calls the check_addr_func that is defined by the application.
 * 	If the application didn't define the check_addr_func, then provide
 * 	the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckAddrPolicy(
	OWPContext	ctx,		/* library context	*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,/* remote addr		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
)
{
	*err_ret = OWPErrOK;

	if(!ctx){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
					"_OWPCallCheckAddrPolicy:No Context!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(!ctx->cfg.check_addr_func)
		return True;

	return (*ctx->cfg.check_addr_func)(ctx->cfg.app_data,local_sa_addr,
							remote_sa_addr,err_ret);
}

/*
 * Function:	_OWPCallCheckControlPolicy
 *
 * Description:
 * 	Calls the check_control_func that is defined by the application.
 * 	If the application didn't define the check_control_func, then provide
 * 	the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckControlPolicy(
	OWPContext	ctx,		/* library context		*/
	OWPSessionMode	mode,		/* requested mode       	*/
	const char	*kid,		/* key identity			*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL		*/
	struct sockaddr	*remote_sa_addr,/* remote addr			*/
	OWPErrSeverity	*err_ret	/* error - return		*/
)
{
	*err_ret = OWPErrOK;

	if(!ctx){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallCheckControlPolicy:No Context!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(!ctx->cfg.check_control_func)
		return True;

	return (*ctx->cfg.check_control_func)(ctx->cfg.app_data,mode,kid,
					local_sa_addr,remote_sa_addr,err_ret);
}

/*
 * Function:	_OWPCallCheckTestPolicy
 *
 * Description:
 * 	Calls the check_test_func that is defined by the application.
 * 	If the application didn't define the check_test_func, then provide
 * 	the default response of True(allowed).
 */
OWPBoolean
_OWPCallCheckTestPolicy(
	OWPControl	cntrl,		/* control handle		*/
	OWPBoolean	local_sender,	/* Is local send or recv	*/
	struct sockaddr	*local,		/* local endpoint		*/
	struct sockaddr	*remote,	/* remote endpoint		*/
	OWPTestSpec	*test_spec,	/* test requested		*/
	OWPErrSeverity	*err_ret	/* error - return		*/
)
{
	OWPContext ctx;
	*err_ret = OWPErrOK;

	if(!cntrl){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallCheckTestPolicy:No Control record!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(!cntrl->ctx->cfg.check_test_func)
		return True;

	return (*cntrl->ctx->cfg.check_test_func)(cntrl->ctx->cfg.app_data,
				cntrl->mode,cntrl->kid,local_sender,local,
				remote,test_spec,err_ret);
}

/*
** Context access function.
*/
OWPContext
OWPGetContext(OWPControl cntrl)
{
	return cntrl->ctx;
}
