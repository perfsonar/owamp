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
extern u_int32_t default_offered_mode;

/*
** On success, this function reads a full client request (decrypting if 
** necessary), saves it into <buf>, and returns its type to the caller 
** for further processing. On failure it returns -1.
** Note: it is a responsibility of the caller to provide
** sufficient memory in <buf>.
*/ 
int
OWPServerReadRequest(OWPControl cntrl, char *buf)
{
	u_int8_t request_type;
	int more_blocks;

	/* Read one block so we can peek at the message type */
	if (_OWPReceiveBlocks(cntrl, buf, 1) < 0)
		return -1;	

	request_type = *(u_int8_t *)buf;
	
	switch (request_type) {
	case OWP_CTRL_REQUEST_SESSION:
		more_blocks = OWP_TEST_REQUEST_BLK_LEN - 1;
		break;
	case OWP_CTRL_START_SESSION:
		more_blocks = OWP_TEST_START_BLK_LEN - 1;
		break;
	case OWP_CTRL_STOP_SESSION:
		more_blocks = OWP_TEST_STOP_BLK_LEN - 1;
		break;
	case OWP_CTRL_RETRIEVE_SESSION:
		more_blocks = OWP_TEST_RETRIEVE_BLK_LEN - 1;
		break;
	default:
		return -1;
		break;
	}

	if (_OWPReceiveBlocks(cntrl, buf + 16, more_blocks) < 0)
		return -1;	

	return request_type;
}

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
** Control connection states - server side.
*/
#define OWP_STATE_IDLE   0
#define OWP_STATE_ACTIVE 1

/*
** The next four functions process messages from client
** during a Control session according to their type. 
** They all assume the the first (16-byte) block of the 
** request has been read and saved in <msg>. Subsequent calls to 
** _OWPReceiveBlocks will start from the second block of the message.
** Note: ProcessTestRequest code may be moved to application
** level (by using a hook if necessary) since it calls fork()
** to spawn off Test sessions.
*/

int
OWPServerProcessTestRequest(OWPControl cntrl, char *msg)
{
	u_int8_t s_version, r_version; 
	OWPPoissonTestSpec test_spec;
	int conf_sender, conf_receiver;
	char rest[MAX_MSG];
	int i;

	u_int8_t* offset = (u_int8_t *)msg + 1;

	s_version = (*offset) >> 4;
	r_version = (*offset) & 0x10;

	/*	void *local, *remote;  */

	if ((s_version != 4) || (s_version != 6) || (s_version != r_version)){
		OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPServerProcessTestRequest: bad IP version(s)");
		return -1;
	}

	switch (s_version) {
	case 4:
		if (r_version != 4){
			OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			     "OWPServerProcessTestRequest: bad IP version(s)");
			return -1;	
		}
		/*
		  ...
		*/
		offset++;
		conf_sender = *(u_int8_t *)offset++;
		conf_receiver = *(u_int8_t *)offset++;

		/* XXX - remember byte-ordering !!! */
		/* send_address = get_addr4(offset, 4);  */

		/* 
		   Now we need to read the rest of the message
		   before doing any further parsing. 
		*/
		if (_OWPReceiveBlocks(cntrl, rest, 9) < 0){
			OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			    "OWPServerProcessTestRequest: _OWPReceiveBlocks");
			return -1;
		}

		/* quickly make sure the last 16 bytes are 0 */
		for (i = 0; i < 4; i++){
			if ( *((u_int32_t *)rest + 128 + 4*i) )
				return -1;
		}

		/*
		offset = (u_int8_t *)rest + 4;
		
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
		if (r_version != 6){
			OWPError(cntrl->ctx, OWPErrWARNING, OWPErrUNKNOWN,
			 "OWPServerProcessTestRequest: bad IP version(s)");
			return -1;
		}
		/*
		  ...
		*/
		break;
	default:
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
** This function is called once the Control connection has been
** accepted. It reads and processes a single Control message.
*/

OWPBoolean
OWPServerControlMain(OWPControl cntrl, OWPErrSeverity *err_ret)
{
	u_int8_t type;
	char msg[MAX_MSG];

	/* Read one block so we can peek at the message type */
	if (_OWPReceiveBlocks(cntrl, msg, 1) < 0)
		return -1;

	type = *(u_int8_t *)msg;

	switch (type) {
	case OWP_CTRL_REQUEST_SESSION:
		OWPServerProcessTestRequest(cntrl, msg);
		break;
	case OWP_CTRL_START_SESSION:
		OWPServerProcessTestStart(cntrl, msg);
		break;
	case OWP_CTRL_STOP_SESSION:
		OWPServerProcessTestStop(cntrl, msg);
		break;
	case OWP_CTRL_RETRIEVE_SESSION:
		OWPServerProcessSessionRetrieve(cntrl, msg);
		break;
	default:
		return False; /* bad message type */
		break;
	}
	
	return True;
}

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
