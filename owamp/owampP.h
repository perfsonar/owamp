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
**	File:		owampP.h
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Wed Mar 20 11:10:33  2002
**
**	Description:	
**	This header file describes the internal-private owamp API.
**
**	testing
*/
#ifndef	OWAMPP_H
#define	OWAMPP_H

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	64
#endif

#include <I2util/util.h>
#include <owamp/owamp.h>

#define	_OWP_DO_CIPHER		(OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/* 
** Lengths (in 16-byte blocks) of various Control messages. 
*/
#define _OWP_RIJNDAEL_BLOCK_SIZE	16
#define _OWP_TEST_REQUEST_BLK_LEN	6
#define _OWP_START_SESSIONS_BLK_LEN	2
#define _OWP_STOP_SESSIONS_BLK_LEN	2
#define _OWP_RETRIEVE_SESSION_BLK_LEN	3
#define _OWP_CONTROL_ACK_BLK_LEN	2
#define _OWP_MAX_MSG_BLK_LEN		_OWP_TEST_REQUEST_BLK_LEN
#define _OWP_MAX_MSG	(_OWP_MAX_MSG_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)
#define	_OWP_TS_REC_SIZE	20

/*
 * Control state constants.
 */
/* initial & invalid */
#define	_OWPStateInitial	(0x00)
#define	_OWPStateInvalid	(0x00)
/* during negotiation */
#define	_OWPStateSetup		(0x01)
/* after negotiation ready for requests */
#define	_OWPStateRequest	(0x02)
/* test sessions are active  */
#define	_OWPStateTest		(0x04)
/*
 * The following states are for partially read messages on the server.
 */
#define _OWPStateTestRequest		(0x08)
#define _OWPStateStartSessions		(0x010)
#define _OWPStateStopSessions		(0x020)
#define _OWPStateRetrieveSession	(0x040)

/* from the server side - "Reading" indicates a partially read request */
#define _OWPStateReading	(_OWPStateTestRequest|_OWPStateStartSessions|_OWPStateStopSessions|_OWPStateRetrieveSession)

#define _OWPStateTestAccept	(0x080)
#define _OWPStateControlAck	(0x0100)
/*
 * "Pending" indicates waiting for server response to a request.
 */
#define	_OWPStatePending	(_OWPStateTestAccept|_OWPStateControlAck|_OWPStateStopSessions)

#define _OWPStateFetch          (0x0200)   /* during fetch-session */

#define	_OWPStateIsInitial(c)	(!(c)->state)
#define	_OWPStateIsSetup(c)	(!(_OWPStateSetup ^ (c)->state))

#define _OWPStateIs(teststate,c)	((teststate & (c)->state))

#define	_OWPStateIsRequest(c)	_OWPStateIs(_OWPStateRequest,c)
#define	_OWPStateIsReading(c)	_OWPStateIs((_OWPStateReading),c)
#define _OWPStateIsPending(c)	_OWPStateIs(_OWPStatePending,c)
#define _OWPStateIsFetch(c)	_OWPStateIs(_OWPStateFetch,c)
#define	_OWPStateIsTest(c)	_OWPStateIs(_OWPStateTest,c)

/*
 * other useful constants.
 */
#define _OWP_ERR_MAXSTRING	(1024)
#define _OWP_MAGIC_FILETYPE	"OwA"

/*
 * Data structures
 */
typedef struct OWPContextRec OWPContextRec;
typedef struct OWPAddrRec OWPAddrRec;
typedef struct OWPControlRec OWPControlRec;

struct OWPContextRec{
	OWPInitializeConfigRec	cfg;
	OWPBoolean		lib_eh;
	I2RandomSource		rand_src;
	OWPControlRec		*cntrl_list;
};

struct OWPAddrRec{
	OWPContext	ctx;

	OWPBoolean	node_set;
	char		node[MAXHOSTNAMELEN+1];

	OWPBoolean	port_set;
	char		port[MAXHOSTNAMELEN+1];

	OWPBoolean	ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	struct sockaddr	*saddr;
	socklen_t	saddrlen;
	int		so_type;	/* socktype saddr works with	*/
	int		so_protocol;	/* protocol saddr works with	*/

	OWPBoolean	fd_user;
	int		fd;
};

typedef struct OWPTestSessionRec OWPTestSessionRec, *OWPTestSession;
struct OWPControlRec{
	/*
	 * Application configuration information.
	 */
	OWPContext		ctx;

	void			*app_data;
	/*
	 * Control connection state information.
	 */
	OWPBoolean		server;	/* this record represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;

	struct timeval		delay_bound;
					/* Very rough upper bound estimate of
					 * rtt.
					 * this is only used to try and make
					 * a rough guess as to how long after
					 * the last packet of a test session
					 * we can reasonably expect all the
					 * packets to have been received.
					 * (Bookkeeping can then start
					 * without too adversely effecting
					 * performace of test.)
					 */
	/*
	 * This field is initialized to zero and used for comparisons
	 * to ensure AES is working.
	 */
	u_int8_t		zero[16];

				/* area for peer's messages		*/
				/* make u_int32_t to get wanted alignment */
				/* Usually cast to u_int8_t when used... */
	u_int32_t		msg[_OWP_MAX_MSG/sizeof(u_int32_t)];

	/*
	 * Address specification and "network" information.
	 * (Control socket addr information)
	 */
	OWPAddr			remote_addr;
	OWPAddr			local_addr;
	int			sockfd;

	/*
	 * Encryption fields
	 */
	char			*kid; /* null if not set - else kid_buffer */
	char			kid_buffer[17];
	keyInstance             encrypt_key;
	keyInstance             decrypt_key;
	u_int8_t		session_key[16];
	u_int8_t		readIV[16];
	u_int8_t		writeIV[16];

	struct OWPControlRec	*next;
	OWPTestSession		tests;
};

struct OWPTestSessionRec{
	OWPControl			cntrl;
	OWPSID				sid;
	OWPAddr				sender;
	OWPAddr				receiver;
	OWPBoolean			send_local;
	OWPBoolean			recv_local;
	void				*send_end_data;
	void				*recv_end_data;
	OWPTestSpec			test_spec;
	OWPnum64			*schedule;
	OWPnum64			last;
	OWPTestSession			next;
};

/*
 * Private api.c prototypes
 */
extern OWPAddr
_OWPAddrAlloc(
	OWPContext	ctx
	);

extern OWPAddr
_OWPAddrCopy(
	OWPAddr		from
	);

extern OWPControl
_OWPControlAlloc(
	OWPContext	ctx,
	void		*app_data,	/* set app_data for this conn */
	OWPErrSeverity	*err_ret
	);

extern OWPTestSession
_OWPTestSessionAlloc(
	OWPControl	cntrl,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec
	);

extern OWPErrSeverity
_OWPTestSessionFree(
	OWPTestSession	tsession,
	OWPAcceptType	aval
	);

extern int
_OWPCreateSID(
	OWPTestSession	tsession
	);

extern int
_OWPTestSessionCreateSchedule(
		OWPTestSession	tsession
		);

/*
 * io.c prototypes
 */
extern int
_OWPConnect(
	int		fd,
	struct sockaddr	*ai_addr,
	size_t		ai_addr_len,
	struct timeval	*tm_out
	   );

extern int
_OWPSendBlocks(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
	      );

extern int
_OWPReceiveBlocks(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
		);

extern int
_OWPEncryptBlocks(
	OWPControl	cntrl,
	u_int8_t	*in_buf,
	int		num_blocks,
	u_int8_t	*out_buf
		);

extern int
_OWPDecryptBlocks(
	OWPControl	cntrl,
	u_int8_t	*in_buf,
	int		num_blocks,
	u_int8_t	*out_buf
		);

extern void
_OWPMakeKey(
	OWPControl	cntrl,
	u_int8_t	*binKey
	);

extern int
OWPEncryptToken(
	u_int8_t	*binKey,
	u_int8_t	*token_in,
	u_int8_t	*token_out
	);

extern int
OWPDecryptToken(
	u_int8_t	*binKey,
	u_int8_t	*token_in,
	u_int8_t	*token_out
	);

/*
 * protocol.c
 */

extern OWPErrSeverity
_OWPWriteServerGreeting(
	OWPControl	cntrl,
	u_int32_t	avail_modes,
	u_int8_t	*challenge	/* [16] */
	);

extern OWPErrSeverity
_OWPReadServerGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,		/* modes available - returned	*/
	u_int8_t	*challenge	/* [16] : challenge - returned	*/
);

extern OWPErrSeverity
_OWPWriteClientGreeting(
	OWPControl	cntrl,
	u_int8_t	*token	/* [32]	*/
	);

extern OWPErrSeverity
_OWPReadClientGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,
	u_int8_t	*token,		/* [32] - return	*/
	u_int8_t	*clientIV	/* [16] - return	*/
	);

extern OWPErrSeverity
_OWPWriteServerOK(
	OWPControl	cntrl,
	OWPAcceptType	code
	);

extern OWPErrSeverity
_OWPReadServerOK(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* ret	*/
	);

extern int
OWPReadRequestType(
	OWPControl	cntrl
	);

extern int
_OWPEncodeV3TestRequest(
	OWPContext	ctx,
	u_int32_t	*msg,
	u_int32_t	*len_ret,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	OWPBoolean	server_conf_sender,
	OWPBoolean	server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
	);

extern OWPErrSeverity
_OWPDecodeV3TestRequest(
	OWPContext	ctx,
	u_int32_t	*msg,
	u_int32_t	msg_len,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	socklen_t	*socklen,
	u_int8_t	*ipvn,
	OWPBoolean	*server_conf_sender,
	OWPBoolean	*server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
	);
	

extern OWPErrSeverity
_OWPWriteTestRequest(
	OWPControl	cntrl,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	OWPBoolean	server_conf_sender,
	OWPBoolean	server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
);

extern OWPErrSeverity
_OWPReadTestRequest(
	OWPControl	cntrl,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	socklen_t	*socklen,
	u_int8_t	*ipvn,
	OWPBoolean	*server_conf_sender,
	OWPBoolean	*server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
);

extern OWPErrSeverity
_OWPWriteTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	acceptval,
	u_int16_t	port,
	OWPSID		sid
	);

extern OWPErrSeverity
_OWPReadTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval,
	u_int16_t	*port,
	OWPSID		sid
	);

extern OWPErrSeverity
_OWPWriteStartSessions(
	OWPControl	cntrl
	);

extern OWPErrSeverity
_OWPReadStartSessions(
	OWPControl	cntrl
);

extern OWPErrSeverity
_OWPWriteStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	);

extern OWPErrSeverity
_OWPReadStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
);

extern OWPErrSeverity
_OWPWriteRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	begin,
	u_int32_t	end,
	OWPSID		sid
	);

extern OWPErrSeverity
_OWPReadRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	*begin,
	u_int32_t	*end,
	OWPSID		sid
);

extern OWPErrSeverity
_OWPWriteControlAck(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	);

extern OWPErrSeverity
_OWPReadControlAck(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
);

extern OWPErrSeverity
_OWPReadFetchHeader(
	OWPControl	cntrl,
	u_int32_t	*num_rec,
	u_int8_t	*typeP
	);

/*
 * TODO:Send session data functions...
 */

/*
 * context.c
 */
extern OWPBoolean
_OWPCallGetAESKey(
	OWPControl	cntrl,		/* control record	*/
	const char	*kid,		/* identifies key	*/
	u_int8_t	*key_ret,	/* key - return		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckControlPolicy(
	OWPControl	cntrl,		/* control record		*/
	OWPSessionMode	mode,		/* requested mode       	*/
	const char	*kid,		/* key identity			*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL		*/
	struct sockaddr	*remote_sa_addr,/* remote addr			*/
	OWPErrSeverity	*err_ret	/* error - return		*/
);

extern OWPBoolean
_OWPCallCheckTestPolicy(
	OWPControl	cntrl,		/* control handle		*/
	OWPBoolean	local_sender,	/* Is local send or recv	*/
	struct sockaddr	*local,		/* local endpoint		*/
	struct sockaddr	*remote,	/* remote endpoint		*/
	OWPTestSpec	*test_spec,	/* test requested		*/
	OWPErrSeverity	*err_ret	/* error - return		*/
);

extern OWPBoolean
_OWPCallEndpointInit(
        OWPControl	cntrl,
	OWPTestSession	tsession,
	OWPAddr		localaddr,
	FILE		*fp,	/* only used if localaddr!=tsession->sender */
	void		**end_data_ret,
	OWPErrSeverity	*err_ret
);

extern OWPBoolean
_OWPCallEndpointInitHook(
        OWPControl      cntrl,
	OWPTestSession	tsession,
	void            **end_data,
	OWPErrSeverity  *err_ret
);

extern OWPBoolean
_OWPCallEndpointStart(
	OWPTestSession	tsession,
	void		**end_data,
	OWPErrSeverity	*err_ret
	);

extern OWPBoolean
_OWPCallEndpointStatus(
	OWPTestSession	tsession,
	void		**end_data,
	OWPAcceptType	*aval,
	OWPErrSeverity	*err_ret
	);

extern OWPBoolean
_OWPCallEndpointStop(
	OWPTestSession	tsession,
	void		**end_data,
	OWPAcceptType	aval,
	OWPErrSeverity	*err_ret
	);

extern OWPContext
OWPGetContext(OWPControl cntrl);

/*
 * error.c
 */
extern OWPErrSeverity
_OWPFailControlSession(
	OWPControl	cntrl,
	int		err
	);

/*
 * time.c
 */

/*
 * En/DecodeTimeStamp functions do not assume any alignment requirements
 * for buf.
 */
extern void
OWPEncodeTimeStamp(
	u_int8_t	buf[8],
	OWPTimeStamp	*tstamp
	);
extern void
OWPDecodeTimeStamp(
	OWPTimeStamp	*tstamp,
	u_int8_t	buf[8]
	);

extern void owp_print_sockaddr(FILE *fp, struct sockaddr *sock);
extern void owp_print_owpaddr(FILE *fp, OWPAddr addr);

#endif	/* OWAMPP_H */
