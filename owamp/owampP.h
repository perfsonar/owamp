/*
 **      $Id$
 */
/************************************************************************
 *                                                                      *
 *                             Copyright (C)  2002                      *
 *                                Internet2                             *
 *                             All Rights Reserved                      *
 *                                                                      *
 ************************************************************************/
/*
 **        File:        owampP.h
 **
 **        Author:      Jeff W. Boote
 **                     Anatoly Karp
 **
 **        Date:        Wed Mar 20 11:10:33  2002
 **
 **        Description:        
 **        This header file describes the internal-private owamp API.
 **
 **        testing
 */
#ifndef        OWAMPP_H
#define        OWAMPP_H

#include <owamp/owamp.h>

#include <I2util/util.h>
#include <I2util/hmac-sha1.h>

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

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN        64
#endif

#ifndef EFTYPE
#define EFTYPE  ENOSYS
#endif


/*
 * Default temporary directory name
 */
#define _OWP_DEFAULT_TMPDIR "/tmp"
#define _OWP_SKIPFILE_FMT   "owpskips.XXXXXX"

/*
 * Default 'count' for pbkdf2() for key generation
 */
#define _OWP_DEFAULT_PBKDF2_COUNT   (2048)

/*
 * Offset's and lengths for various file versions.
 */
#define _OWP_TESTREC_OFFSET (40)
#define _OWP_DATARECV2_SIZE (24)
#define _OWP_DATARECV3_SIZE (25)
#define _OWP_DATAREC_SIZE _OWP_DATARECV3_SIZE
#define _OWP_MAXDATAREC_SIZE _OWP_DATAREC_SIZE
#define _OWP_SKIPREC_SIZE   (8)

/*
 * Size of a single AES block
 */
#define _OWP_RIJNDAEL_BLOCK_SIZE    16

/*
 * Size of token,salt - SetupResponseMessage
 */
#define _OWP_TOKEN_SIZE (64)
#define _OWP_SALT_SIZE (16)

/*
 * The FETCH buffer is the smallest multiple of both the _OWP_DATAREC_SIZE
 * and the _OWP_RIJNDAEL_BLOCK_SIZE. The following must be true:
 * _OWP_FETCH_AES_BLOCKS * _OWP_RIJNDAEL_BLOCK_SIZE == _OWP_FETCH_BUFFSIZE
 * _OWP_FETCH_DATAREC_BLOCKS * _OWP_DATAREC_SIZE == _OWP_FETCH_BUFFSIZE
 */
#define _OWP_FETCHV2_BUFFSIZE       48
#define _OWP_FETCHV2_AES_BLOCKS     3
#define _OWP_FETCHV2_DATAREC_BLOCKS 2
#define _OWP_FETCHV3_BUFFSIZE       400
#define _OWP_FETCHV3_AES_BLOCKS     25
#define _OWP_FETCHV3_DATAREC_BLOCKS 16
#define _OWP_FETCH_BUFFSIZE         (_OWP_FETCHV3_BUFFSIZE)
#define _OWP_FETCH_AES_BLOCKS       (_OWP_FETCHV3_AES_BLOCKS)
#define _OWP_FETCH_DATAREC_BLOCKS   (_OWP_FETCHV3_DATAREC_BLOCKS)

#if (_OWP_FETCH_BUFFSIZE != (_OWP_RIJNDAEL_BLOCK_SIZE * _OWP_FETCH_AES_BLOCKS))
#error "Fetch Buffer is mis-sized for AES block size!"
#endif
#if (_OWP_FETCH_BUFFSIZE != (_OWP_DATAREC_SIZE * _OWP_FETCH_DATAREC_BLOCKS))
#error "Fetch Buffer is mis-sized for Test Record Size!"
#endif
/* 
 ** Lengths (in 16-byte blocks) of various Control messages. 
 */
#define _OWP_TEST_REQUEST_BLK_LEN   7
#define _OWP_START_SESSIONS_BLK_LEN 2
#define _OWP_STOP_SESSIONS_BLK_LEN  2
#define _OWP_FETCH_SESSION_BLK_LEN  3
#define _OWP_START_ACK_BLK_LEN      2
#define _OWP_FETCH_ACK_BLK_LEN      2
#define _OWP_MAX_MSG_BLK_LEN        _OWP_FETCHV3_AES_BLOCKS

#define _OWP_MAX_MSG_SIZE               (_OWP_MAX_MSG_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)
#define _OWP_TEST_REQUEST_PREAMBLE_SIZE (_OWP_TEST_REQUEST_BLK_LEN*_OWP_RIJNDAEL_BLOCK_SIZE)

/*
 * Control state constants.
 * (Used to keep track of partially read messages, and to make debugging
 * control session state easier to manage.)
 */
/* initial & invalid */
#define _OWPStateInitial    (0x0000)
#define _OWPStateInvalid    (0x0000)
/* during negotiation */
#define _OWPStateSetup      (0x0001)
#define _OWPStateUptime     (_OWPStateSetup << 1)
/* after negotiation ready for requests */
#define _OWPStateRequest    (_OWPStateUptime << 1)
/* test sessions are active  */
#define _OWPStateTest       (_OWPStateRequest << 1)
/*
 * The following states are for partially read messages on the server.
 */
#define _OWPStateTestRequest        (_OWPStateTest << 1)
#define _OWPStateTestRequestSlots   (_OWPStateTestRequest << 1)
#define _OWPStateStartSessions      (_OWPStateTestRequestSlots << 1)
#define _OWPStateStopSessions       (_OWPStateStartSessions << 1)
#define _OWPStateFetchSession       (_OWPStateStopSessions << 1)
#define _OWPStateTestRequestTW      (_OWPStateFetchSession << 1)
#define _OWPStateAcceptSession         (_OWPStateTestRequestTW << 1)
#define _OWPStateStartAck           (_OWPStateAcceptSession << 1)
/* during fetch-session */
#define _OWPStateFetchAck           (_OWPStateStartAck << 1)
#define _OWPStateFetching           (_OWPStateFetchAck << 1)
#define _OWPStateFetchingRecords    (_OWPStateFetching << 1)

/* Reading indicates partial read request-ReadRequestType without remainder */
#define _OWPStateReading            (_OWPStateTestRequest|_OWPStateStartSessions|_OWPStateStopSessions|_OWPStateFetchSession)

/*
 * "Pending" indicates waiting for server response to a request.
 */
#define _OWPStatePending            (_OWPStateAcceptSession|_OWPStateStartAck|_OWPStateStopSessions|_OWPStateFetchAck)


#define _OWPStateIsInitial(c)       (!(c)->state)
#define _OWPStateIsSetup(c)         (!(_OWPStateSetup ^ (c)->state))
#define _OWPStateIs(teststate,c)    ((teststate & (c)->state))
#define _OWPStateIsRequest(c)       _OWPStateIs(_OWPStateRequest,c)
#define _OWPStateIsReading(c)       _OWPStateIs((_OWPStateReading),c)
#define _OWPStateIsPending(c)       _OWPStateIs(_OWPStatePending,c)
#define _OWPStateIsFetchSession(c)  _OWPStateIs(_OWPStateFetchSession,c)
#define _OWPStateIsFetching(c)      _OWPStateIs(_OWPStateFetching,c)
#define _OWPStateIsTest(c)          _OWPStateIs(_OWPStateTest,c)
#define _OWPStateIsTestReqTW(c)          _OWPStateIs(_OWPStateTestRequestTW,c)

/*
 * other useful constants.
 */
#define _OWP_ERR_MAXSTRING  (1024)
#define _OWP_MAGIC_FILETYPE "OwA"
#define _OWP_DEFAULT_FUZZTIME (1.0)

/*
 * Data structures
 */
typedef struct OWPContextRec OWPContextRec;
typedef struct OWPControlRec OWPControlRec;

#define _OWP_CONTEXT_TABLE_SIZE 64
#define _OWP_CONTEXT_MAX_KEYLEN 64

struct OWPContextRec{
    OWPBoolean      lib_eh;
    I2ErrHandle     eh;
    I2Table         table;
    I2RandomSource  rand_src;
    uint32_t        pbkdf2_count;
    OWPControlRec   *cntrl_list;
};

typedef struct OWPTestSessionRec OWPTestSessionRec, *OWPTestSession;
struct OWPControlRec{
    /*
     * Application configuration information.
     */
    OWPContext              ctx;

    /*
     * Hash for maintaining Policy state data.
     */
    I2Table                 table;

    /*
     * Control connection state information.
     */
    OWPBoolean              server;     /* this record represents server */
    int                     state;      /* current state of connection */
    OWPSessionMode          mode;
    OWPBoolean              twoway;

    /*
     * Very rough upper bound estimate of rtt.
     * Used by clients to estimate a good "start" time for tests that
     * is just beyond the amount of time it takes to request the test.
     */
    OWPNum64                rtt_bound;

    /*
     * This field is initialized to zero and used for comparisons
     * to ensure AES is working.
     */
    char                    zero[16];

    /*
     * area for peer's messages, make uint32_t to get integer alignment.
     * Cast to char * when used... C99 indicates (char *) as only valid
     * type for punning like this.
     */
    uint32_t               msg[_OWP_MAX_MSG_SIZE/sizeof(uint32_t)];

    /*
     * Address specification and "network" information.
     * (Control socket addr information)
     */
    I2Addr                  remote_addr;
    I2Addr                  local_addr;
    int                     sockfd;

    /*
     * Encryption fields
     */
    /* null if not set - else userid_buffer */
    char                    *userid;
    OWPUserID               userid_buffer;
    keyInstance             encrypt_key;
    keyInstance             decrypt_key;
    uint8_t                 aessession_key[16];
    uint8_t                 readIV[16];
    uint8_t                 writeIV[16];

    uint8_t                 hmac_key[32];
    I2HMACSha1Context       send_hmac_ctx;
    I2HMACSha1Context       recv_hmac_ctx;

    int                     *retn_on_intr;

    struct OWPControlRec    *next;
    OWPTestSession          tests;
};

typedef struct OWPLostPacketRec OWPLostPacketRec, *OWPLostPacket;
struct OWPLostPacketRec{
    uint32_t       seq;
    OWPBoolean      hit;
    OWPNum64        relative;
    struct timespec absolute;   /* absolute time */
    OWPLostPacket   next;
};

typedef struct _OWPSkipRec _OWPSkipRec, *_OWPSkip;
struct _OWPSkipRec{
    OWPSkipRec  sr;
    _OWPSkip    next;
};

/*
 * This type holds all the information needed for an endpoint to be
 * managed.
 */
typedef struct OWPEndpointRec{
    OWPControl          cntrl;
    OWPTestSession      tsession;

#ifndef        NDEBUG
    I2Boolean           childwait;
#endif

    OWPAcceptType       acceptval;
    pid_t               child;
    int                 wopts;
    OWPBoolean          send;
    OWPBoolean          twoway;
    int                 sockfd;
    int                 skiprecfd;
    off_t               skiprecsize;
    I2Addr              remoteaddr;
    I2Addr              localaddr;

    /*
     * crypt fields
     */
    uint8_t             aesbytes[_OWP_RIJNDAEL_BLOCK_SIZE];
    keyInstance         aeskey;
    keyInstance         aes_tw_reply_key;
    uint8_t             hmac_key[32];
    I2HMACSha1Context   hmac_ctx;

    char                fname[PATH_MAX];
    FILE                *userfile;          /* from _OWPOpenFile */
    FILE                *datafile;          /* correct buffering */
    char                *fbuff;

    struct timespec     start;
    struct timespec     enddelay;
    char                *payload;

    size_t              len_payload;


    /* Keep track of "lost" packets */
    uint32_t            numalist;
    OWPLostPacket       lost_allocated;
    OWPLostPacket       freelist;
    OWPLostPacket       begin;
    OWPLostPacket       end;
    I2Table             lost_packet_buffer;

    /* Keep track of which packets the sender actually sent */
    uint32_t            nextseq;
    uint32_t            num_allocskip;
    _OWPSkip            skip_allocated;
    _OWPSkip            free_skiplist;
    _OWPSkip            head_skip;
    _OWPSkip            tail_skip;

} OWPEndpointRec, *OWPEndpoint;

#define _OWPSLOT_BUFSIZE        10
struct OWPTestSessionRec{
    OWPControl          cntrl;
    OWPSID              sid;
    I2Addr              sender;
    I2Addr              receiver;
    OWPBoolean          conf_sender;
    OWPBoolean          conf_receiver;
    OWPTestSpec         test_spec;
    OWPSlot             slot_buffer[_OWPSLOT_BUFSIZE];

    OWPEndpoint         endpoint;
    void                *closure; /* per/test app data */

    /* schedule */
    OWPScheduleContext  sctx;

    /* For send sessions, what packets were actually sent */
    uint32_t           nextseq;
    uint32_t           nskips;
    OWPSkipRec          skips;

    OWPTestSession      next;
};

/*
 * Private api.c prototypes
 */

extern OWPTestSession
_OWPTestSessionAlloc(
        OWPControl      cntrl,
        I2Addr          sender,
        OWPBoolean      server_conf_sender,
        I2Addr          receiver,
        OWPBoolean      server_conf_receiver,
        OWPTestSpec     *test_spec
        );

extern OWPErrSeverity
_OWPTestSessionFree(
        OWPTestSession  tsession,
        OWPAcceptType   aval
        );

extern int
_OWPCreateSID(
        OWPTestSession  tsession
        );

/*
 * This structure is used to hold the initial "fixed"
 * fields in an owp file. Filled in with _OWPReadDataHeaderInitial().
 */
typedef struct _OWPSessionHeaderInitialRec{
    /*
     * File info, and fields for all versions
     */
    OWPBoolean              header;     /* True if version >= 2
                                         * indicates test req available
                                         */
    struct stat             sbuf;
    uint32_t               version;
    uint32_t               rec_size;

                            /* same as oset_datarecs for version >= 3 */
    off_t                   hdr_len;

    /*
     * Added for Version 2 (also test req)
     */
    OWPSessionFinishedType  finished;

    /*
     * Added for Version 3
     */
    uint32_t               next_seqno;
    uint32_t               num_skiprecs;
    uint32_t               num_datarecs;

    off_t                   oset_skiprecs;
    off_t                   oset_datarecs;
} _OWPSessionHeaderInitialRec, *_OWPSessionHeaderInitial;

extern OWPBoolean
_OWPReadDataHeaderInitial(
        OWPContext                  ctx,
        FILE                        *fp,
        _OWPSessionHeaderInitial    phdr
        );

extern OWPBoolean
_OWPWriteDataHeaderFinished(
        OWPContext  ctx,
        FILE        *fp,
        uint32_t   finished,
        uint32_t   next_seqno
        );

extern OWPBoolean
_OWPCleanDataRecs(
        OWPContext      cntrl,
        OWPTestSession  tptr,
        uint32_t        next_seqno,
        OWPTimeStamp    stoptime,
        uint32_t        *max_recv,  /* out: max received index */
        off_t           *off_start  /* out: beginning of questionable data */
        );
/*
 * io.c prototypes
 */
extern int
_OWPSendBlocksIntr(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks,
        int         *retn_on_intr
        );

extern int
_OWPReceiveBlocksIntr(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks,
        int         *retn_on_intr
        );

extern int
_OWPSendBlocks(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks
        );

extern int
_OWPReceiveBlocks(
        OWPControl  cntrl,
        uint8_t     *buf,
        int         num_blocks
        );

extern int
_OWPEncryptBlocks(
        OWPControl  cntrl,
        uint8_t     *in_buf,
        int         num_blocks,
        uint8_t     *out_buf
        );

extern int
_OWPDecryptBlocks(
        OWPControl  cntrl,
        uint8_t     *in_buf,
        int         num_blocks,
        uint8_t     *out_buf
        );

extern void
_OWPMakeKey(
        OWPControl  cntrl,
        uint8_t     *binKey
        );

extern int
OWPEncryptToken(
        const uint8_t   *pf,
        size_t          pf_len,
        const uint8_t   salt[16],
        uint32_t        count,
        const uint8_t   token_in[_OWP_TOKEN_SIZE],
        uint8_t         token_out[_OWP_TOKEN_SIZE]
        );

extern int
OWPDecryptToken(
        const uint8_t   *pf,
        size_t          pf_len,
        const uint8_t   salt[16],
        uint32_t        count,
        const uint8_t   token_in[_OWP_TOKEN_SIZE],
        uint8_t         token_out[_OWP_TOKEN_SIZE]
        );

extern void
_OWPSendHMACAdd(
        OWPControl  cntrl,
        const char  *txt,
        uint32_t    num_blocks
        );

extern void
_OWPSendHMACDigestClear(
        OWPControl  cntrl,
        char        digest[16]
        );

extern void
_OWPRecvHMACAdd(
        OWPControl  cntrl,
        const char  *txt,
        uint32_t    num_blocks
        );

extern OWPBoolean
_OWPRecvHMACCheckClear(
        OWPControl  cntrl,
        char        check[16]
        );

/*
 * protocol.c
 */
extern OWPErrSeverity
_OWPWriteServerGreeting(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    avail_modes,
        uint8_t     *challenge,  /* [16] */
        uint8_t     *salt,       /* [16] */
        uint32_t    count
        );

extern OWPErrSeverity
_OWPReadServerGreeting(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    *mode,      /* modes available - returned   */
        uint8_t     *challenge, /* [16] : challenge - returned  */
        uint8_t     *salt,      /* [16] : salt - returned       */
        uint32_t    *count
        );

extern OWPErrSeverity
_OWPWriteSetupResponse(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint8_t     *token          /* [64] */
        );

extern OWPErrSeverity
_OWPReadSetupResponse(
        OWPControl  cntrl,
        int         *retn_on_intr,
        uint32_t    *mode,
        uint8_t     *token,         /* [32] - return    */
        uint8_t     *clientIV       /* [16] - return    */
        );

extern OWPErrSeverity
_OWPWriteServerStart(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   code,
        OWPNum64        uptime
        );

extern OWPErrSeverity
_OWPReadServerStart(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,     /* ret        */
        OWPNum64        *uptime_ret     /* ret        */
        );

extern OWPErrSeverity
_OWPReadServerUptime(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPNum64        *uptime_ret
        );

extern int
_OWPEncodeTestRequestPreamble(
        OWPContext      ctx,
        uint32_t        *msg,
        uint32_t        *len_ret,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender,
        OWPBoolean      server_conf_receiver,
        OWPBoolean      twoway,
        OWPSID          sid,
        OWPTestSpec     *tspec
        );

extern OWPErrSeverity
_OWPDecodeTestRequestPreamble(
        OWPContext      ctx,
        OWPBoolean      request,
        uint32_t        *msg,
        uint32_t        msg_len,
        OWPBoolean      is_twoway,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        socklen_t       *socklen,
        uint8_t         *ipvn,
        OWPBoolean      *server_conf_sender,
        OWPBoolean      *server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *test_spec
        );

extern OWPErrSeverity
_OWPEncodeSlot(
        uint32_t    *msg,   /* [4] - one block/ 16 bytes 32 bit aligned */
        OWPSlot     *slot
        );
extern OWPErrSeverity
_OWPDecodeSlot(
        OWPSlot     *slot,
        uint32_t    *msg    /* [4] - one block/ 16 bytes 32 bit aligned */
        );

extern OWPErrSeverity
_OWPWriteTestRequest(
        OWPControl      cntrl,
        int             *retn_on_intr,
        struct sockaddr *sender,
        struct sockaddr *receiver,
        OWPBoolean      server_conf_sender,
        OWPBoolean      server_conf_receiver,
        OWPSID          sid,
        OWPTestSpec     *test_spec
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
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPTestSession  *test_session,
        OWPAcceptType   *accept_ret
        );

extern OWPBoolean
_OWPEncodeDataRecord(
        char        buf[_OWP_MAXDATAREC_SIZE],
        OWPDataRec  *rec
        );

extern OWPBoolean
_OWPDecodeDataRecord(
        uint32_t    file_version,
        OWPDataRec  *rec,
        /* V0,V2 == [_OWP_DATARECV2_SIZE], V3 == [_OWP_DATAREC_SIZE] */
        char        *buf
        );

extern OWPErrSeverity
_OWPWriteAcceptSession(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        uint16_t        port,
        OWPSID          sid
        );

extern OWPErrSeverity
_OWPReadAcceptSession(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,
        uint16_t        *port,
        OWPSID          sid
        );

extern OWPErrSeverity
_OWPWriteStartSessions(
        OWPControl      cntrl,
        int             *retn_on_intr
        );

extern OWPErrSeverity
_OWPReadStartSessions(
        OWPControl      cntrl,
        int             *retn_on_intr
        );

extern void
_OWPEncodeSkipRecord(
        uint8_t buf[_OWP_SKIPREC_SIZE],
        OWPSkip skip
        );

extern void
_OWPDecodeSkipRecord(
        OWPSkip skip,
        char    buf[_OWP_SKIPREC_SIZE]
        );

extern OWPErrSeverity
_OWPWriteStopSessions(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        uint32_t        num_sessions
        );

extern OWPErrSeverity
_OWPReadStopSessions(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,
        OWPTimeStamp    stoptime
        );

extern OWPErrSeverity
_OWPWriteFetchSession(
        OWPControl      cntrl,
        int             *retn_on_intr,
        uint32_t        begin,
        uint32_t        end,
        OWPSID          sid
        );

extern OWPErrSeverity
_OWPReadFetchSession(
        OWPControl      cntrl,
        int             *retn_on_intr,
        uint32_t        *begin,
        uint32_t        *end,
        OWPSID          sid
        );

extern OWPErrSeverity
_OWPWriteFetchAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval,
        uint8_t         finished,
        uint32_t        next_seqno,
        uint32_t        num_skiprecs,
        uint32_t        num_datarecs
        );

extern OWPErrSeverity
_OWPReadFetchAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval,
        uint8_t         *finished,
        uint32_t        *next_seqno,
        uint32_t        *num_skiprecs,
        uint32_t        *num_datarecs
        );

extern OWPErrSeverity
_OWPWriteStartAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   acceptval
        );

extern OWPErrSeverity
_OWPReadStartAck(
        OWPControl      cntrl,
        int             *retn_on_intr,
        OWPAcceptType   *acceptval
        );

/*
 * context.c
 */

extern OWPControl
_OWPControlAlloc(
        OWPContext      ctx,
        OWPBoolean      twoway,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
_OWPCallGetPF(
        OWPContext      ctx,        /* context record       */
        const OWPUserID userid,     /* identifies key       */
        uint8_t         **pf_ret,   /* pass-phrase - return */
        size_t          *pf_len,    /* len - return         */
        void            **pf_free,  /* free if set - return */
        OWPErrSeverity  *err_ret    /* error - return       */
        );

extern OWPBoolean
_OWPCallCheckControlPolicy(
        OWPControl      cntrl,          /* control record           */
        OWPSessionMode  mode,           /* requested mode           */
        const char      *userid,        /* key identity             */
        struct sockaddr *local_sa_addr, /* local addr or NULL       */
        struct sockaddr *remote_sa_addr,/* remote addr              */
        OWPErrSeverity  *err_ret        /* error - return           */
        );

extern OWPBoolean
_OWPCallCheckTestPolicy(
        OWPControl      cntrl,          /* control handle           */
        OWPBoolean      local_sender,   /* Is local send or recv    */
        struct sockaddr *local,         /* local endpoint           */
        struct sockaddr *remote,        /* remote endpoint          */
        socklen_t       sa_len,         /* saddr sizes              */
        OWPTestSpec     *test_spec,     /* test requested           */
        void            **closure,      /* app data/per test        */
        OWPErrSeverity  *err_ret        /* error - return           */
        );

extern OWPBoolean
_OWPCallCheckFetchPolicy(
        OWPControl      cntrl,          /* control handle           */
        struct sockaddr *local,         /* local endpoint           */
        struct sockaddr *remote,        /* remote endpoint          */
        socklen_t       sa_len,         /* saddr sizes              */
        uint32_t        begin,          /* first seq_no             */
        uint32_t        end,            /* last seq_no              */
        OWPSID          sid,            /* sid                      */
        void            **closure,      /* app data/per test        */
        OWPErrSeverity  *err_ret        /* error - return           */
        );

extern void
_OWPCallTestComplete(
        OWPTestSession  tsession,
        OWPAcceptType   aval
        );

/*
 * non-NULL closure indicates "receiver" - NULL indicates R/O Fetch.
 */
extern FILE *
_OWPCallOpenFile(
        OWPControl      cntrl,          /* control handle       */
        void            *closure,       /* app data/per test    */
        OWPSID          sid,            /* sid for datafile     */
        char            fname_ret[PATH_MAX+1]
        );

extern void
_OWPCallCloseFile(
        OWPControl      cntrl,
        void            *closure,
        FILE            *fp,
        OWPAcceptType   aval
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
        OWPControl      cntrl,
        OWPTestSession  tsession,
        I2Addr          localaddr,
        FILE            *fp,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
_OWPEndpointInitHook(
        OWPControl      cntrl,
        OWPTestSession  tsession,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        );

extern OWPBoolean
_OWPEndpointStart(
        OWPEndpoint     ep,
        OWPErrSeverity  *err_ret
        );

extern void
_OWPEndpointStatus(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
        );

extern void
_OWPEndpointStop(
        OWPEndpoint     ep,
        OWPAcceptType   *aval,
        OWPErrSeverity  *err_ret
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
        OWPControl      cntrl,
        int             err
        );

/*
 * time.c
 */

extern int
_OWPInitNTP(
        OWPContext      ctx
        );

struct timespec *
_OWPGetTimespec(
        OWPContext      ctx,
        struct timespec *ts,
        uint32_t       *esterr,
        uint8_t        *synchronized
        );

/*
 * En/DecodeTimeStamp functions do not assume any alignment requirements
 * for buf. (Most functions in protocol.c assume uint32_t alignment.)
 */
extern void
_OWPEncodeTimeStamp(
        uint8_t         buf[8],
        OWPTimeStamp    *tstamp
        );
extern OWPBoolean
_OWPEncodeTimeStampErrEstimate(
        uint8_t         buf[2],
        OWPTimeStamp    *tstamp
        );
extern void
_OWPDecodeTimeStamp(
        OWPTimeStamp    *tstamp,
        uint8_t         buf[8]
        );
extern OWPBoolean
_OWPDecodeTimeStampErrEstimate(
        OWPTimeStamp    *tstamp,
        uint8_t         buf[2]
        );

extern OWPBoolean
_OWPIsInterface(
        const char *interface
        );

#endif        /* OWAMPP_H */
