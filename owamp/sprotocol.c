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
**	File:		sprotocol.c
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Wed Apr  24 10:42:12  2002
**
**	Description:	This file contains the private functions that
**			speak the owamp protocol directly from the
**			server point of view.
**			(i.e. read and write the data and save it
**			to structures for the rest of the api to deal
**			with.)
**
*/
#include "./owampP.h"

/*
** Accept or reject the Control Connection request.
** Code = CTRL_ACCEPT/CTRL_REJECT with the obvious meaning.
*/
int
_OWPServerOK(OWPControl cntrl, u_int8_t code)
{
	char buf[MAX_MSG];
	memset(buf, 0, 32);
	*(u_int8_t *)(buf+15) = code;
	if (cntrl->mode && OWP_MODE_AUTHENTICATED){
		memcpy(buf + 16, cntrl->writeIV, 16);
	}
	_OWPSendBlocks(cntrl, buf, 2);
}

/*
** This function is used to determine type of the received client request.
** On success, it MUST be followed by a call to one of
*/
u_int8_t
OWPGetType(OWPControl cntrl)
{
	/* Read one block so we can peek at the message type */
	if (_OWPReceiveBlocks(cntrl, cntrl->msg, 1) < 0)
		return 0;	

	return *(u_int8_t *)(cntrl->msg);
}

/*
** Control connection states - server side.
*/
#define OWP_STATE_IDLE   0
#define OWP_STATE_ACTIVE 1


#define OWP_RCV_MASK 0xF
#define BAD_IPVN(x) (((x) != 4) && ((x) != 6))
#define BAD_BOOLEAN(x) ((x) != 0 && (x) != 1)

/* 
** This function parses a Test Request. It returns 0 on success,
** and -1 on failure. It also fills a RequestSessionSpec struct
** and returns it on success.
*/

int
OWPParseTestRequest(
		    OWPControl cntrl, 
		    OWPAddr sender, 
		    OWPAddr receiver,
		    OWPBoolean *conf_sender,
		    OWPBoolean *conf_receiver,
		    OWPTestSpec *test_spec,
		    OWPSID sid
		    )
{
	/* RequestSessionSpec request; */
	u_int8_t           s_ipvn, r_ipvn;
	char               *ptr;
	u_int8_t           *offset;
	int                i;

	if (_OWPReceiveBlocks(cntrl, cntrl->msg + 16, 
			      OWP_TEST_REQUEST_BLK_LEN - 1) < 0)
			return -1;

	offset = (u_int8_t *)(cntrl->msg) + 1;

	s_ipvn = (*offset) >> 4;
	r_ipvn = (*offset) & OWP_RCV_MASK;

	/*	void *local, *remote;  */

	if ((s_ipvn != 4) || (s_ipvn != 6) || (s_ipvn != r_ipvn)){
		OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPParseTestRequest: bad IP version(s)");
		return -1;
	}

	/* quickly make sure the last 16 bytes are 0 */
	ptr = (cntrl->msg) + 16 * (OWP_TEST_REQUEST_BLK_LEN - 1);
	for (i = 0; i < 4; i++){
		if ( *(u_int32_t *)ptr )
			return -1;
		ptr += 4;
	}

	offset++;

	/* XXX - this has to go into cntrl record */
	if (BAD_BOOLEAN(*offset)){
		OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPParseTestRequest: bad booleans(s) for conf");
		return -1;
	}
	*conf_sender = (*offset)? True : False;
	offset++;

	if (BAD_BOOLEAN(*offset)){
		OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPParseTestRequest: bad booleans(s) for conf");
		return -1;
	}
	*conf_receiver = (*offset)? True : False;
	offset++;

	/* Assume offset points at Sender Address now */
	switch (s_ipvn) {
	case 4:
		/*
		  ...
		*/

		/* XXX - remember byte-ordering !!! */
		/* send_address = get_addr4(offset, 4);  */

		/*
		
		recv_address = get_u32(offset); 
		offset += 16;

		send_port = get_u16(offset);
		offset += 2;

		recv_port = get_u16(offset);
		offset += 2;
		
		get_sid(offset, sid);
		offset += 16;

		inv_lambda = get_u32(offset);
		offset += 4;

		packets = get_u32(offset);
		offset += 4;

		pad_length = get_u32(offset);
		offset += 4;

		get_start_time(offset, start_time);
		offset += 8;

		pd = get_u32(offset);
		*/
		break;
	case 6:
		/*
		  ...
		*/
		break;
	default:
		/* CANNOT HAPPEN */
		OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPServerProcessTestRequest: bad IP version(s)");
		return -1;	
	}
}
 
int
OWPServerProcessTestStart(OWPControl cntrl, char *msg)
{
	
}

int
OWPServerProcessTestStop(OWPControl cntrl, char *msg)
{
	
}

int
OWPServerProcessSessionRetrieve(OWPControl cntrl, char *msg)
{
	
}

#define OWP_CTRL_REQUEST_SESSION 1
#define OWP_CTRL_START_SESSION 2
#define OWP_CTRL_STOP_SESSION 3
#define OWP_CTRL_RETRIEVE_SESSION 4

/*
** This function reads KID, Token and ClientIV of the Client greeting.
** and saves them in relevant fields of cntrl structure. It returns
** 0 on success, and -1 on failure.
*/

int
ParseRest(OWPControl cntrl)
{
	
}

OWPBoolean
OWPServerCheckAddrPolicy(OWPContext ctx, 
			 struct sockaddr *addr, 
			 OWPErrSeverity *err_ret
			 )
{
	return _OWPCallCheckAddrPolicy(ctx, NULL, addr, err_ret);
}

void
OWPServerAcceptSession(OWPControl cntrl, int code)
{
	
}
