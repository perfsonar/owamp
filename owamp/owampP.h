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

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#include "config.h"

#if	!HAVE_ERRNO_H || !HAVE_NETDB_H || !HAVE_STDLIB_H || !HAVE_SYS_PARAM_H
#error	Missing Header!
#endif

#if	!HAVE_GETADDRINFO || !HAVE_SOCKET
#error	Missing needed networking capabilities! (getaddrinfo and socket)
#endif

#if	!HAVE_MALLOC || !HAVE_MEMSET
#error	Missing needed memory functions!
#endif
#endif	/* HAVE_CONFIG_H */

#ifndef	HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

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

#include "rijndael-api-fst.h"

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
#define _OWPStateReadingTestRequest	(0x08)
#define _OWPStateReadingStartSessions	(0x0F)
#define _OWPStateReadingStopSessions	(0x010)
#define _OWPStateReadingRetrieveSession	(0x020)

#define _OWPStateTestAccept	(0x040)
#define _OWPStateControlAck	(0x080)

#define	_OWPStateIsInitial(c)	(!(c)->state)
#define	_OWPStateIsSetup(c)	(!(_OWPStateSetup ^ (c)->state))
#define	_OWPStateIsRequest(c)	((_OWPStateRequest & (c)->state))
#define	_OWPStateIsTest(c)	((_OWPStateTest & (c)->state))

#define _OWPStateIs(teststate,c)	((teststate & (c)->state))

/*
 * other useful constants.
 */
#define _OWP_ERR_MAXSTRING	(1024)

/*
 * Data structures
 */
typedef struct OWPContextRec OWPContextRec;
typedef struct OWPAddrRec OWPAddrRec;
typedef struct OWPControlRec OWPControlRec;

struct OWPContextRec{
	OWPInitializeConfigRec	cfg;
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

	OWPBoolean	fd_user;
	int		fd;
};

typedef struct OWPTestSessionRec OWPTestSessionRec, *OWPTestSession;
struct OWPControlRec{
	/*
	 * Application configuration information.
	 */
	OWPContext		ctx;

	/*
	 * Control connection state information.
	 */
	OWPBoolean		server;	/* this record represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;

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
	char			kid_buffer[9];
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
	OWPBoolean			server_conf_sender;
	OWPBoolean			server_conf_receiver;
	void				*send_end_data;
	void				*recv_end_data;
	OWPTestSpec			test_spec;
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

extern void
_OWPTestSessionFree(
	OWPTestSession	tsession
	);

/*
 * io.c prototypes
 */
extern ssize_t
_OWPReadn(
	int	fd,
	void	*buff,
	size_t	n
	 );

extern ssize_t
_OWPWriten(
	int		fd,
	const void	*buff,
	size_t		n
	  );

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
/*
 * Valid values for "accept" - this will be added to for the purpose of
 * enumerating the reasons for rejection.
 *
 * TODO:Get the additional "accept" values added to the spec.
 */
typedef enum{
	_OWP_CNTRL_INVALID=-1,
	_OWP_CNTRL_ACCEPT=0x0,
	_OWP_CNTRL_REJECT=0x1,
	_OWP_CNTRL_SERVER_FAILURE=0x2
} OWPAcceptType;

extern int
_OWPWriteServerGreeting(
	OWPControl	cntrl,
	u_int32_t	avail_modes,
	u_int8_t	*challenge	/* [16] */
	);

extern int
_OWPReadServerGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,		/* modes available - returned	*/
	u_int8_t	*challenge	/* [16] : challenge - returned	*/
);

extern int
_OWPWriteClientGreeting(
	OWPControl	cntrl,
	u_int8_t	*token	/* [32]	*/
	);

extern int
_OWPReadClientGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode,
	u_int8_t	*token,		/* [32] - return	*/
	u_int8_t	*clientIV	/* [16] - return	*/
	);

extern int
_OWPWriteServerOK(
	OWPControl	cntrl,
	OWPAcceptType	code
	);

extern int
_OWPReadServerOK(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* ret	*/
	);

extern u_int8_t
OWPReadRequestType(
	OWPControl	cntrl
	);

extern int
_OWPWriteTestRequest(
	OWPControl	cntrl,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	OWPBoolean	server_conf_sender,
	OWPBoolean	server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*test_spec
);

extern int
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

extern int
_OWPWriteTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	acceptval,
	u_int16_t	port,
	OWPSID		sid
	);

extern int
_OWPReadTestAccept(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval,
	u_int16_t	*port,
	OWPSID		sid
	);

extern int
_OWPWriteStartSessions(
	OWPControl	cntrl
	);

extern int
_OWPReadStartSessions(
	OWPControl	cntrl
);

extern int
_OWPWriteStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	);

extern int
_OWPReadStopSessions(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
);

extern int
_OWPWriteRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	begin,
	u_int32_t	end,
	OWPSID		sid
	);

extern int
_OWPReadRetrieveSession(
	OWPControl	cntrl,
	u_int32_t	*begin,
	u_int32_t	*end,
	OWPSID		sid
);

extern int
_OWPWriteControlAck(
	OWPControl	cntrl,
	OWPAcceptType	acceptval
	);

extern int
_OWPReadControlAck(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
);

/*
 * TODO:Send session data functions...
 */

/*
 * context.c
 */
extern OWPBoolean
_OWPCallGetAESKey(
	OWPContext	ctx,		/* library context	*/
	const char	*kid,		/* identifies key	*/
	u_int8_t	*key_ret,	/* key - return		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckAddrPolicy(
	OWPContext	ctx,		/* library context	*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,/* remote addr		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckControlPolicy(
	OWPContext	ctx,		/* library context		*/
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
        OWPControl      cntrl,
	void            **end_data_ret,
        OWPBoolean      send,
	OWPAddr         localaddr,
	OWPTestSpec     *test_spec,
	OWPSID          sid_ret,	/* only used if !send */
	OWPErrSeverity  *err_ret
);

extern OWPBoolean
_OWPCallEndpointInitHook(
        OWPControl      cntrl,
	void            *end_data,
	OWPAddr         remoteaddr,
	OWPSID		sid,
	OWPErrSeverity  *err_ret
);

extern OWPContext
OWPGetContext(OWPControl cntrl);

/*
 * time.c
 */

extern void
OWPEncodeTimeStamp(
	u_int32_t	buf[2],
	OWPTimeStamp	*tstamp
	);

extern void
OWPDecodeTimeStamp(
	OWPTimeStamp	*tstamp,
	u_int32_t	buf[2]
	);

#endif	/* OWAMPP_H */
