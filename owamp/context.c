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
OWPBool
_OWPCallGetAESKey(
	OWPContext	ctx,		/* library context	*/
	OWPKID		kid,		/* identifies key	*/
	OWPKey		*key_ret,	/* key - return		*/
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
	if(!ctx->get_aes_key_func)
		return False;

	return (*ctx->get_aes_key_func)(ctx->app_data,kid,key_ret,err_ret);
}

/*
 * Function:	_OWPCallCheckAddrPolicy
 *
 * Description:
 * 	Calls the check_addr_func that is defined by the application.
 * 	If the application didn't define the check_addr_func, then provide
 * 	the default response of True(allowed).
 */
OWPBool
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
	if(!ctx->check_addr_func)
		return True;

	return (*ctx->check_addr_func)(ctx->app_data,local_sa_addr,
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
OWPBool
_OWPCallCheckControlPolicy(
	OWPContext	ctx,		/* library context	*/
	OWPSessionModes	mode,		/* reqested mode	*/
	OWPKID		kid,		/* key identity		*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,/* remote addr		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
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
	if(!ctx->check_control_func)
		return True;

	return (*ctx->check_control_func)(ctx->app_data,modes,kid,
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
OWPBool
_OWPCallCheckTestPolicy(
	OWPContext	ctx,		/* library context		*/
	OWPTestSpec	*test_spec,	/* test requested		*/
	OWPEndpoint	local,		/* local endpoint		*/
	OWPEndpoint	remote,		/* remote endpoint		*/
	OWPErrSeverity	*err_ret	/* error - return		*/
)
{
	*err_ret = OWPErrOK;

	if(!ctx){
		OWPErrorLine(NULL,OWPLine,OWPErrFATAL,OWPErrUNKNOWN,
				"_OWPCallCheckTestPolicy:No Context!");
		*err_ret = OWPErrFATAL;
		return False;
	}

	/*
	 * Default action is to allow anything.
	 */
	if(!ctx->check_test_func)
		return True;

	return (*ctx->check_test_func)(ctx->app_data,test_spec,local,remote,
								err_ret);
}
