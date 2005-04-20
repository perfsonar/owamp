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
 * Offset's and lengths for various file versions.
 */
#define _OWP_TESTREC_OFFSET     (size_t)40
#define	_OWP_DATARECV2_SIZE	(size_t)24
#define	_OWP_DATARECV3_SIZE	(size_t)25
#define	_OWP_DATAREC_SIZE	_OWP_DATARECV3_SIZE
#define _OWP_SKIPREC_SIZE       (size_t)8

/*
 * Size of a single AES block
 */
#define _OWP_RIJNDAEL_BLOCK_SIZE	(size_t)16

/*
 * The FETCH buffer is the smallest multiple of both the _OWP_DATAREC_SIZE
 * and the _OWP_RIJNDAEL_BLOCK_SIZE. The following must be true:
 * _OWP_FETCH_AES_BLOCKS * _OWP_RIJNDAEL_BLOCK_SIZE == _OWP_FETCH_BUFFSIZE
 * _OWP_FETCH_DATAREC_BLOCKS * _OWP_DATAREC_SIZE == _OWP_FETCH_BUFFSIZE
 */
#define _OWP_FETCHV2_BUFFSIZE		48
#define _OWP_FETCHV2_AES_BLOCKS		3
#define _OWP_FETCHV2_DATAREC_BLOCKS	2
#define _OWP_FETCHV3_BUFFSIZE		400
#define _OWP_FETCHV3_AES_BLOCKS		25
#define _OWP_FETCHV3_DATAREC_BLOCKS	16
#define _OWP_FETCH_BUFFSIZE		_OWP_FETCHV3_BUFFSIZE
#define _OWP_FETCH_AES_BLOCKS		_OWP_FETCHV3_AES_BLOCKS
#define _OWP_FETCH_DATAREC_BLOCKS	_OWP_FETCHV3_DATAREC_BLOCKS

#if (_OWP_FETCH_BUFFSIZE != (_OWP_RIJNDAEL_BLOCK_SIZE * _OWP_FETCH_AES_BLOCKS))
#error "Fetch Buffer is mis-sized for AES block size!"
#endif
#if (_OWP_FETCH_BUFFSIZE != (_OWP_DATAREC_SIZE * _OWP_FETCH_DATAREC_BLOCKS))
#error "Fetch Buffer is mis-sized for Test Record Size!"
#endif
/* 
 ** Lengths (in 16-byte blocks) of various Control messages. 
 */
#define _OWP_TEST_REQUEST_BLK_LEN	7
#define _OWP_START_SESSIONS_BLK_LEN	2
#define _OWP_STOP_SESSIONS_BLK_LEN	2
#define _OWP_FETCH_SESSION_BLK_LEN	3
#define _OWP_START_ACK_BLK_LEN	        2
#define _OWP_FETCH_ACK_BLK_LEN	        2
#define _OWP_MAX_MSG_BLK_LEN		_OWP_FETCHV3_AES_BLOCKS
#define _OWP_MAX_MSG_SIZE	(_OWP_MAX_MSG_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)
#define _OWP_TEST_REQUEST_PREAMBLE_SIZE	(_OWP_TEST_REQUEST_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)

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
#define _OWPStateStartAck		(_OWPStateTestAccept << 1)
/* during fetch-session */
#define _OWPStateFetchAck		(_OWPStateStartAck << 1)
#define _OWPStateFetching		(_OWPStateFetchAck << 1)
#define _OWPStateFetchingRecords	(_OWPStateFetching << 1)

/* Reading indicates partial read request-ReadRequestType without remainder */
#define _OWPStateReading	(_OWPStateTestRequest|_OWPStateStartSessions|_OWPStateStopSessions|_OWPStateFetchSession)

/*
 * "Pending" indicates waiting for server response to a request.
 */
#define	_OWPStatePending	(_OWPStateTestAccept|_OWPStateStartAck|_OWPStateStopSessions|_OWPStateFetchAck)


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
 * Byte-ordering macros for 64 bit values
 */
#ifndef htonll
#define htonll(h64)                                                     \
    {                                                                   \
        u_int64_t   n64_;                                               \
        u_int8_t    *t8_;                                               \
        u_int64_t   t64_ = h64;                                         \
        t8_ = (u_int8_t*)&n64_;                                         \
        *(u_int32_t*)&t8_[4] = htonl(t64 & 0xFFFFFFFFUL);               \
        t64_ >>= 32;                                                    \
        *(u_int32_t*)&t8_[0] = htonl(t64 & 0xFFFFFFFFUL);               \
        n64_;                                                           \
    }
#endif

#ifndef ntohll
#define ntohll(n64)                                                     \
    {                                                                   \
        u_int64_t   h64_;                                               \
        u_int8_t    *t8_;                                               \
        t8_ = (u_int8_t*)&n64;                                          \
        h64_ = ntohl(*(u_int32_t*)&t8_[0]);                             \
        h64_ <<= 32;                                                    \
        h64_ |= ntohl(*(u_int32_t*)&t8_[4]);                            \
    }
#endif

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
    I2Table		table;
    I2RandomSource	rand_src;
    OWPControlRec	*cntrl_list;
};

struct OWPAddrRec{
    OWPContext	    ctx;

    OWPBoolean	    node_set;
    char	    node[MAXHOSTNAMELEN+1];

    OWPBoolean	    port_set;
    char	    port[MAXHOSTNAMELEN+1];

    OWPBoolean	    ai_free;	/* free ai list directly...*/
    struct addrinfo *ai;

    struct sockaddr *saddr;
    socklen_t	    saddrlen;
    int		    so_type;	/* socktype saddr works with	*/
    int		    so_protocol;	/* protocol saddr works with	*/

    OWPBoolean	    fd_user;
    int		    fd;
};

typedef struct OWPTestSessionRec OWPTestSessionRec, *OWPTestSession;
struct OWPControlRec{
    /*
     * Application configuration information.
     */
    OWPContext		    ctx;

    /*
     * Hash for maintaining Policy state data.
     */
    I2Table		    table;

    /*
     * Control connection state information.
     */
    OWPBoolean		    server;	/* this record represents server */
    int			    state;	/* current state of connection */
    OWPSessionMode	    mode;

    /*
     * Very rough upper bound estimate of
     * rtt.
     * Used by clients to estimate a
     * good "start" time for tests that
     * is just beyond the amount of time
     * it takes to request the test.
     */
    OWPNum64		    rtt_bound;

    /*
     * This field is initialized to zero and used for comparisons
     * to ensure AES is working.
     */
    u_int8_t		    zero[16];

    /* area for peer's messages		*/
    /* make u_int32_t to get wanted alignment */
    /* Usually cast to u_int8_t when used... */
    u_int32_t		    msg[_OWP_MAX_MSG_SIZE/sizeof(u_int32_t)];

    /*
     * Address specification and "network" information.
     * (Control socket addr information)
     */
    OWPAddr		    remote_addr;
    OWPAddr		    local_addr;
    int			    sockfd;

    /*
     * Encryption fields
     */
    /* null if not set - else userid_buffer */
    char		    *userid;
    OWPUserID		    userid_buffer;
    keyInstance             encrypt_key;
    keyInstance             decrypt_key;
    u_int8_t		    session_key[16];
    u_int8_t		    readIV[16];
    u_int8_t		    writeIV[16];

    int			    *retn_on_intr;

    struct OWPControlRec    *next;
    OWPTestSession	    tests;
};

typedef struct OWPLostPacketRec OWPLostPacketRec, *OWPLostPacket;
struct OWPLostPacketRec{
    u_int32_t	    seq;
    OWPBoolean	    hit;
    OWPNum64	    relative;
    struct timespec absolute;	/* absolute time */
    OWPLostPacket   next;
};

typedef struct OWPSkipRec OWPSkipRec, *OWPSkip;
struct OWPSkipRec{
    u_int32_t   begin;
    u_int32_t   end;
    OWPSkip     next;
};

/*
 * This type holds all the information needed for an endpoint to be
 * managed.
 */
typedef struct OWPEndpointRec{
    OWPControl	    cntrl;
    OWPTestSession  tsession;

#ifndef	NDEBUG
    I2Boolean	    childwait;
#endif

    OWPAcceptType   acceptval;
    pid_t	    child;
    int		    wopts;
    OWPBoolean	    send;
    int		    sockfd;
    int             skiprecfd;
    off_t           skiprecsize;
    OWPAddr	    remoteaddr;
    OWPAddr	    localaddr;

    char	    fname[PATH_MAX];
    FILE	    *userfile;	/* from _OWPOpenFile */
    FILE	    *datafile;	/* correct buffering */
    char	    *fbuff;

    struct timespec start;
    u_int8_t	    *payload;

    size_t	    len_payload;


    /* Keep track of "lost" packets */
    u_int32_t	    numalist;
    OWPLostPacket   lost_allocated;
    OWPLostPacket   freelist;
    OWPLostPacket   begin;
    OWPLostPacket   end;
    I2Table	    lost_packet_buffer;

    /* Keep track of which packets the sender actually sent */
    u_int32_t       nextseq;
    u_int32_t       num_allocskip;
    OWPSkip         skip_allocated;
    OWPSkip         free_skiplist;
    OWPSkip         head_skip;
    OWPSkip         tail_skip;

} OWPEndpointRec, *OWPEndpoint;

#define _OWPSLOT_BUFSIZE	10
struct OWPTestSessionRec{
    OWPControl		cntrl;
    OWPSID		sid;
    OWPAddr		sender;
    OWPAddr		receiver;
    OWPBoolean		conf_sender;
    OWPBoolean		conf_receiver;
    OWPTestSpec		test_spec;
    OWPSlot		slot_buffer[_OWPSLOT_BUFSIZE];

    OWPEndpoint		endpoint;
    void		*closure; /* per/test app data */

    /* schedule */
    OWPScheduleContext  sctx;

    /* For send sessions, what packets were actually sent */
    u_int32_t           nextseq;
    u_int32_t           nskips;
    OWPSkipRec          skips;

    OWPTestSession	next;
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

/*
 * This structure is used to hold the initial "fixed"
 * fields in an owp file. Filled in with _OWPReadDataHeaderInitial().
 */
typedef struct _OWPSessionHeaderInitialRec{
    /*
     * File info, and fields for all versions
     */
    OWPBoolean      header;         /* True if version >= 2
                                     * indicates test req available
                                     */
    struct stat     sbuf;
    u_int32_t       version;
    off_t           hdr_len;        /* same as oset_datarecs for version >= 3 */

    /*
     * Added for Version 2 (also test req)
     */
    u_int32_t       finished;

    /*
     * Added for Version 3
     */
    u_int32_t       next_seqno;
    u_int32_t       num_skiprecs;
    u_int32_t       num_datarecs;

    off_t           oset_skiprecs;
    off_t           oset_datarecs;
} _OWPSessionHeaderInitialRec, *_OWPSessionHeaderInitial;

extern OWPBoolean
_OWPReadDataHeaderInitial(
        OWPContext                  ctx,
        FILE                        *fp,
        _OWPSessionHeaderInitial    phdr
        );

extern int
_OWPWriteDataHeaderFinished(
        OWPContext	ctx,
        FILE		*fp,
        u_int32_t	finished
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
        OWPBoolean	request,
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
        u_int8_t	buf[_OWP_DATAREC_SIZE],
        OWPDataRec	*rec
        );

extern OWPBoolean
_OWPDecodeDataRecord(
        u_int32_t	file_version,
        OWPDataRec	*rec,
        /* V0,V2 == [_OWP_DATARECV2_SIZE], V3 == [_OWP_DATAREC_SIZE] */
        u_int8_t	*buf
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

extern void
_OWPEncodeSkipRecord(
        u_int8_t    buf[_OWP_SKIPREC_SIZE],
        OWPSkip     skip
        );

extern void
_OWPDecodeSkipRecord(
        OWPSkip     skip,
        u_int8_t    buf[_OWP_SKIPREC_SIZE]
        );

extern OWPErrSeverity
_OWPWriteStopSessions(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        u_int32_t       num_sessions
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

extern _OWPErrSeverity
_OWPWriteFetchAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        u_int8_t        finished,
        u_int32_t       next_seqno,
        u_int32_t       num_skiprecs,
        u_int32_t       num_datarecs
        );

extern _OWPErrSeverity
_OWPReadFetchAck(
        OWPControl      cntrl,
        OWPAcceptType   *acceptval,
        u_int8_t        *finished,
        u_int32_t       *next_seqno,
        u_int32_t       *num_skiprecs,
        u_int32_t       *num_datarecs
        );

extern OWPErrSeverity
_OWPWriteStartAck(
        OWPControl	cntrl,
        int		*retn_on_intr,
        OWPAcceptType	acceptval
        );

extern OWPErrSeverity
_OWPReadStartAck(
        OWPControl	cntrl,
        OWPAcceptType	*acceptval
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
        OWPAcceptType   *aval,
        OWPErrSeverity	*err_ret
        );

extern OWPBoolean
_OWPEndpointInitHook(
        OWPControl      cntrl,
        OWPTestSession	tsession,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
_OWPEndpointStart(
        OWPEndpoint	ep,
        OWPErrSeverity	*err_ret
        );

extern void
_OWPEndpointStatus(
        OWPEndpoint	ep,
        OWPAcceptType	*aval,
        OWPErrSeverity	*err_ret
        );

extern void
_OWPEndpointStop(
        OWPEndpoint	ep,
        OWPAcceptType	*aval,
        OWPErrSeverity	*err_ret
        );

extern void
_OWPEndpointFree(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
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

struct timespec *
_OWPGetTimespec(
        OWPContext	ctx,
        struct timespec	*ts,
        u_int32_t	*esterr,
        int		*sync
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
