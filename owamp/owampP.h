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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	64
#endif

#include <I2util/util.h>
#include <owamp/owamp.h>

/* 
** Lengths (in 16-byte blocks) of various Control messages. 
*/
#define _OWP_RIJNDAEL_BLOCK_SIZE	16
#define _OWP_TEST_REQUEST_BLK_LEN	7
#define _OWP_START_SESSIONS_BLK_LEN	2
#define _OWP_STOP_SESSIONS_BLK_LEN	2
#define _OWP_FETCH_SESSION_BLK_LEN	3
#define _OWP_CONTROL_ACK_BLK_LEN	2
#define _OWP_MAX_MSG_BLK_LEN		_OWP_TEST_REQUEST_BLK_LEN
#define _OWP_MAX_MSG	(_OWP_MAX_MSG_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)
#define _OWP_TEST_REQUEST_PREAMBLE_SIZE	(_OWP_TEST_REQUEST_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)
#define	_OWP_TESTREC_SIZE	24

/*
 * The FETCH buffer is the smallest multiple of both the _OWP_TS_REC_SIZE
 * and the _OWP_RIJNDAEL_BLOCK_SIZE. The following must be true:
 * _OWP_FETCH_AES_BLOCKS * _OWP_RIJNDAEL_BLOCK_SIZE == _OWP_FETCH_BUFFSIZE
 * _OWP_FETCH_TESTREC_BLOCKS * _OWP_TESTREC_SIZE == _OWP_FETCH_BUFFSIZE
 */
#define _OWP_FETCH_BUFFSIZE		48
#define _OWP_FETCH_AES_BLOCKS		3
#define _OWP_FETCH_TESTREC_BLOCKS	2

#if (_OWP_FETCH_BUFFSIZE != (_OWP_RIJNDAEL_BLOCK_SIZE * _OWP_FETCH_AES_BLOCKS))
#error "Fetch Buffer is mis-sized for AES block size!"
#endif
#if (_OWP_FETCH_BUFFSIZE != (_OWP_TESTREC_SIZE * _OWP_FETCH_TESTREC_BLOCKS))
#error "Fetch Buffer is mis-sized for Test Record Size!"
#endif

/*
 * Control state constants.
 */
/* initial & invalid */
#define	_OWPStateInitial		(0x0000)
#define	_OWPStateInvalid		(0x0000)
/* during negotiation */
#define	_OWPStateSetup			(0x0001)
#define	_OWPStateUptime			(_OWPStateSetup << 1)
/* after negotiation ready for requests */
#define	_OWPStateRequest		(_OWPStateUptime << 1)
/* test sessions are active  */
#define	_OWPStateTest			(_OWPStateRequest << 1)
/*
 * The following states are for partially read messages on the server.
 */
#define _OWPStateTestRequest		(_OWPStateTest << 1)
#define _OWPStateTestRequestSlots	(_OWPStateTestRequest << 1)
#define _OWPStateStartSessions		(_OWPStateTestRequestSlots << 1)
#define _OWPStateStopSessions		(_OWPStateStartSessions << 1)
#define _OWPStateFetchSession		(_OWPStateStopSessions << 1)
#define _OWPStateTestAccept		(_OWPStateFetchSession << 1)
#define _OWPStateControlAck		(_OWPStateTestAccept << 1)
/* during fetch-session */
#define _OWPStateFetching		(_OWPStateControlAck << 1)
#define _OWPStateFetchingRecords	(_OWPStateFetching << 1)

/* Reading indicates partial read request-ReadRequestType without remainder */
#define _OWPStateReading	(_OWPStateTestRequest|_OWPStateStartSessions|_OWPStateStopSessions|_OWPStateFetchSession)

/*
 * "Pending" indicates waiting for server response to a request.
 */
#define	_OWPStatePending	(_OWPStateTestAccept|_OWPStateControlAck|_OWPStateStopSessions)


#define	_OWPStateIsInitial(c)	(!(c)->state)
#define	_OWPStateIsSetup(c)	(!(_OWPStateSetup ^ (c)->state))

#define _OWPStateIs(teststate,c)	((teststate & (c)->state))

#define	_OWPStateIsRequest(c)	_OWPStateIs(_OWPStateRequest,c)
#define	_OWPStateIsReading(c)	_OWPStateIs((_OWPStateReading),c)
#define _OWPStateIsPending(c)	_OWPStateIs(_OWPStatePending,c)
#define _OWPStateIsFetchSession(c)	_OWPStateIs(_OWPStateFetchSession,c)
#define _OWPStateIsFetching(c)	_OWPStateIs(_OWPStateFetching,c)
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

#define _OWP_CONTEXT_TABLE_SIZE	64
#define _OWP_CONTEXT_MAX_KEYLEN	64

struct OWPContextRec{
	OWPBoolean		lib_eh;
	I2ErrHandle		eh;
	I2Table			table;
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

	/*
	 * Hash for maintaining Policy state data.
	 */
	I2Table			table;

	/*
	 * Control connection state information.
	 */
	OWPBoolean		server;	/* this record represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;

				/*
				 * Very rough upper bound estimate of
				 * rtt.
				 * Used by clients to estimate a
				 * good "start" time for tests that
				 * is just beyond the amount of time
				 * it takes to request the test.
				 */
	OWPNum64		rtt_bound;
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
				/* null if not set - else userid_buffer */
	u_int8_t		*userid;
	OWPUserID		userid_buffer;
	keyInstance             encrypt_key;
	keyInstance             decrypt_key;
	u_int8_t		session_key[16];
	u_int8_t		readIV[16];
	u_int8_t		writeIV[16];

	int			*retn_on_intr;

	struct OWPControlRec	*next;
	OWPTestSession		tests;
};

typedef struct OWPLostPacketRec OWPLostPacketRec, *OWPLostPacket;
struct OWPLostPacketRec{
	u_int64_t	seq;
	OWPBoolean	hit;
	OWPNum64	relative;
	struct timespec	absolute;	/* absolute time */
	OWPLostPacket	next;
};


/*
 * This type holds all the information needed for an endpoint to be
 * managed.
 */
typedef struct OWPEndpointRec{
	OWPControl		cntrl;
	OWPTestSession		tsession;

#ifndef	NDEBUG
	I2Boolean		childwait;
#endif

	OWPAcceptType		acceptval;
	pid_t			child;
	int			wopts;
	OWPBoolean		send;
	int			sockfd;
	OWPAddr			remoteaddr;

	char			fname[PATH_MAX];
	FILE			*userfile;	/* from _OWPOpenFile */
	FILE			*datafile;	/* correct buffering */
	char			*fbuff;

	struct timespec		start;
	u_int8_t		*payload;

	size_t			len_payload;

	OWPLostPacket		freelist;
	OWPLostPacket		begin;
	OWPLostPacket		end;
	u_int64_t		numalist;
	I2Table			lost_packet_buffer;

} OWPEndpointRec, *OWPEndpoint;

#define _OWPSLOT_BUFSIZE	10
struct OWPTestSessionRec{
	OWPControl			cntrl;
	OWPSID				sid;
	OWPAddr				sender;
	OWPAddr				receiver;
	OWPBoolean			conf_sender;
	OWPBoolean			conf_receiver;
	OWPTestSpec			test_spec;
	OWPSlot				slot_buffer[_OWPSLOT_BUFSIZE];

	OWPEndpoint			endpoint;
	void				*closure; /* per/test app data */

	OWPScheduleContext		sctx;
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

#define	_OWP_SESSION_FIN_ERROR	0
#define	_OWP_SESSION_FIN_NORMAL	1
#define _OWP_SESSION_FIN_INCOMPLETE	2

extern int
_OWPWriteDataHeaderFinished(
		OWPContext	ctx,
		FILE		*fp,
		u_int32_t	finished
		);

extern int
_OWPReadDataHeaderInitial(
		OWPContext	ctx,
		FILE		*fp,
		u_int32_t	*ver,
		u_int32_t	*fin,	/* only set if (*ver >= 2) */
		off_t		*hdr_off,
		struct stat	*stat_buf
		);

/*
 * io.c prototypes
 */
extern int
_OWPSendBlocksIntr(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
	      );

extern int
_OWPReceiveBlocksIntr(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	int		*retn_on_intr
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
	u_int8_t	*challenge,	/* [16] */
	int		*retn_on_intr
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
	u_int8_t	*clientIV,	/* [16] - return	*/
	int		*retn_on_intr
	);

extern OWPErrSeverity
_OWPWriteServerOK(
	OWPControl	cntrl,
	OWPAcceptType	code,
	OWPNum64	uptime,
	int		*retn_on_intr
	);

extern OWPErrSeverity
_OWPReadServerOK(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval	/* ret	*/
	);

extern OWPErrSeverity
_OWPReadServerUptime(
	OWPControl	cntrl,
	OWPNum64	*uptime_ret
	);

extern int
_OWPEncodeTestRequestPreamble(
	OWPContext	ctx,
	u_int32_t	*msg,
	u_int32_t	*len_ret,
	struct sockaddr	*sender,
	struct sockaddr	*receiver,
	OWPBoolean	server_conf_sender,
	OWPBoolean	server_conf_receiver,
	OWPSID		sid,
	OWPTestSpec	*tspec
	);

extern OWPErrSeverity
_OWPDecodeTestRequestPreamble(
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
_OWPEncodeSlot(
	u_int32_t	*msg,	/* [4] - one block/ 16 bytes 32 bit aligned */
	OWPSlot		*slot
	);
extern OWPErrSeverity
_OWPDecodeSlot(
	OWPSlot		*slot,
	u_int32_t	*msg	/* [4] - one block/ 16 bytes 32 bit aligned */
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

/*
 * This function can be called from a server or client context. From the
 * server it is reading an actual new request. From the client it is part
 * of a FetchSession response. The server code MUST set the accept_ret
 * pointer to a valid OWPAcceptType record. This record will be filled
 * in with the appropriate AcceptType value for a response. The client
 * code MUST set this to NULL.
 */
extern OWPErrSeverity
_OWPReadTestRequest(
	OWPControl	cntrl,
	int		*retn_on_intr,
	OWPTestSession	*test_session,
	OWPAcceptType	*accept_ret
	);

extern OWPBoolean
_OWPEncodeDataRecord(
	u_int8_t	buf[24],
	OWPDataRec	*rec
	);

extern OWPBoolean
_OWPDecodeDataRecord(
	OWPDataRec	*rec,
	u_int8_t	buf[24]
	);

extern OWPErrSeverity
_OWPWriteTestAccept(
	OWPControl	cntrl,
	int		*retn_on_intr,
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
	OWPControl	cntrl,
	int		*retn_on_intr
);

extern OWPErrSeverity
_OWPWriteStopSessions(
	OWPControl	cntrl,
	int		*retn_on_intr,
	OWPAcceptType	acceptval
	);

extern OWPErrSeverity
_OWPReadStopSessions(
	OWPControl	cntrl,
	int		*retn_on_intr,
	OWPAcceptType	*acceptval
);

extern OWPErrSeverity
_OWPWriteFetchSession(
	OWPControl	cntrl,
	u_int32_t	begin,
	u_int32_t	end,
	OWPSID		sid
	);

extern OWPErrSeverity
_OWPReadFetchSession(
	OWPControl	cntrl,
	int		*retn_on_intr,
	u_int32_t	*begin,
	u_int32_t	*end,
	OWPSID		sid
);

extern OWPErrSeverity
_OWPWriteControlAck(
	OWPControl	cntrl,
	int		*retn_on_intr,
	OWPAcceptType	acceptval
	);

extern OWPErrSeverity
_OWPReadControlAck(
	OWPControl	cntrl,
	OWPAcceptType	*acceptval
);

extern OWPErrSeverity
_OWPWriteFetchRecordsHeader(
	OWPControl	cntrl,
	int		*retn_on_intr,
	u_int64_t	num_rec
	);

extern OWPErrSeverity
_OWPReadFetchRecordsHeader(
	OWPControl	cntrl,
	u_int64_t	*num_rec
	);

/*
 * context.c
 */

extern OWPControl
_OWPControlAlloc(
	OWPContext	ctx,
	OWPErrSeverity	*err_ret
	);

extern OWPBoolean
_OWPCallGetAESKey(
	OWPContext	ctx,		/* context record	*/
	const char	*userid,	/* identifies key	*/
	u_int8_t	*key_ret,	/* key - return		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckControlPolicy(
	OWPControl	cntrl,		/* control record		*/
	OWPSessionMode	mode,		/* requested mode       	*/
	const char	*userid,	/* key identity			*/
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
	socklen_t	sa_len,		/* saddr sizes			*/
	OWPTestSpec	*test_spec,	/* test requested		*/
	void		**closure,	/* app data/per test		*/
	OWPErrSeverity	*err_ret	/* error - return		*/
);

extern void
_OWPCallTestComplete(
	OWPTestSession	tsession,
	OWPAcceptType	aval
	);

/*
 * non-NULL closure indicates "receiver" - NULL indicates R/O Fetch.
 */
extern FILE *
_OWPCallOpenFile(
	OWPControl	cntrl,		/* control handle		*/
	void		*closure,	/* app data/per test		*/
	OWPSID		sid,		/* sid for datafile		*/
	char		fname_ret[PATH_MAX+1]
	);

extern void
_OWPCallCloseFile(
	OWPControl	cntrl,
	void		*closure,
	FILE		*fp,
	OWPAcceptType	aval
	);


/* endpoint.c */

/*
 * The endpoint init function is responsible for opening a socket, and
 * allocating a local port number.
 * If this is a recv endpoint, it is also responsible for allocating a
 * session id.
 */
extern OWPBoolean
_OWPEndpointInit(
	OWPControl	cntrl,
	OWPTestSession	tsession,
	OWPAddr		localaddr,
	FILE		*fp,
	OWPErrSeverity	*err_ret
);

extern OWPBoolean
_OWPEndpointInitHook(
        OWPControl      cntrl,
	OWPTestSession	tsession,
	OWPErrSeverity  *err_ret
);

extern OWPBoolean
_OWPEndpointStart(
	OWPEndpoint	ep,
	OWPErrSeverity	*err_ret
	);

extern OWPBoolean
_OWPEndpointStatus(
	OWPEndpoint	ep,
	OWPAcceptType	*aval,
	OWPErrSeverity	*err_ret
	);

extern OWPBoolean
_OWPEndpointStop(
	OWPEndpoint	ep,
	OWPAcceptType	aval,
	OWPErrSeverity	*err_ret
	);

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

extern int
_OWPInitNTP(
	OWPContext	ctx
	);
/*
 * En/DecodeTimeStamp functions do not assume any alignment requirements
 * for buf. (Most functions in protocol.c assume u_int32_t alignment.)
 */
extern void
_OWPEncodeTimeStamp(
	u_int8_t	buf[8],
	OWPTimeStamp	*tstamp
	);
extern OWPBoolean
_OWPEncodeTimeStampErrEstimate(
	u_int8_t	buf[2],
	OWPTimeStamp	*tstamp
	);
extern void
_OWPDecodeTimeStamp(
	OWPTimeStamp	*tstamp,
	u_int8_t	buf[8]
	);
extern OWPBoolean
_OWPDecodeTimeStampErrEstimate(
	OWPTimeStamp	*tstamp,
	u_int8_t	buf[2]
	);

#endif	/* OWAMPP_H */
