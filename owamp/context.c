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
#include "owampP.h"
#include "endpoint.h"

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
	u_int8_t	*key_ret,	/* key - return		*/
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
 * Calls the endpoint_init func defined by the application.
 */
OWPBoolean
_OWPCallEndpointInit(
	OWPControl	cntrl,
	void		**end_data_ret,
	OWPBoolean	send,
	OWPAddr		localaddr,
	OWPTestSpec	*test_spec,
	OWPSID		sid,
	OWPErrSeverity	*err_ret
)
{
	OWPEndpointInitFunc	init_func = OWPDefEndpointInit;
	void			*def_app_data;

	if(!cntrl){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallCheckTestPolicy:No Control record!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(cntrl->ctx->cfg.endpoint_init_func){
		init_func = cntrl->ctx->cfg.endpoint_init_func;
		def_app_data = cntrl->ctx->cfg.app_data;
	}else{
		def_app_data = cntrl->ctx;
	}

	if( (*err_ret = (*init_func)(def_app_data,end_data_ret,send,
			localaddr,test_spec,sid)) < OWPErrWARNING)
		return False;
	return True;
}

/*
 * Calls the endpoint_init_hook func defined by the application.
 */
OWPBoolean
_OWPCallEndpointInitHook(
	OWPControl	cntrl,
	void		*end_data,
	OWPAddr		remoteaddr,
	OWPSID		sid,
	OWPErrSeverity	*err_ret
)
{
	OWPEndpointInitHookFunc	initH_func = OWPDefEndpointInitHook;
	void			*def_app_data;

	if(!cntrl){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallCheckTestPolicy:No Control record!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(cntrl->ctx->cfg.endpoint_init_hook_func){
		initH_func = cntrl->ctx->cfg.endpoint_init_hook_func;
		def_app_data = cntrl->ctx->cfg.app_data;
	}else{
		def_app_data = cntrl->ctx;
	}

	if( (*err_ret = (*initH_func)(def_app_data,end_data,remoteaddr,sid)) <
								OWPErrWARNING)
		return False;
	return True;
}

OWPBoolean
_OWPCallEndpointStart(
	OWPTestSession	tsession,
	void		*end_data,
	OWPErrSeverity	*err_ret
)
{
	OWPEndpointStartFunc	func = OWPDefEndpointStart;
	void			*def_app_data;

	if(!tsession){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallEndpointStart:No TestSession record!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	if(tsession->cntrl->ctx->cfg.endpoint_start_func){
		func = tsession->cntrl->ctx->cfg.endpoint_start_func;
		def_app_data = tsession->cntrl->ctx->cfg.app_data;
	}else{
		def_app_data = tsession->cntrl->ctx;
	}

	if( (*err_ret = (*func)(def_app_data,end_data)) < OWPErrWARNING)
		return False;
	return True;
}

OWPBoolean
_OWPCallEndpointStop(
	OWPTestSession	tsession,
	void		*end_data,
	OWPAcceptType	aval,
	OWPErrSeverity	*err_ret
)
{
	OWPEndpointStopFunc	func = OWPDefEndpointStop;
	void			*def_app_data;

	if(!tsession){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallEndpointStop:No TestSession record!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	if(tsession->cntrl->ctx->cfg.endpoint_stop_func){
		func = tsession->cntrl->ctx->cfg.endpoint_stop_func;
		def_app_data = tsession->cntrl->ctx->cfg.app_data;
	}else{
		def_app_data = tsession->cntrl->ctx;
	}

	if( (*err_ret = (*func)(def_app_data,end_data,aval)) < OWPErrWARNING)
		return False;
	return True;
}

/*
** Context access function.
*/
OWPContext
OWPGetContext(OWPControl cntrl)
{
	return cntrl->ctx;
}
