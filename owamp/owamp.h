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
**	File:		owamp.h
**
**	Author:		Jeff W. Boote
**			Anatoly Karp
**
**	Date:		Wed Mar 20 11:10:33  2002
**
**	Description:	
**	This header file describes the owamp API. The owamp API is intended
**	to provide a portable layer for implementing the owamp protocol.
*/
#ifndef	OWAMP_H
#define	OWAMP_H

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#include <owamp/config.h>

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

#ifndef	OWP_DATADIR
#define OWP_DATADIR "/data"
#endif
#ifndef OWP_PATH_SEPARATOR
#define	OWP_PATH_SEPARATOR	"/"
#endif
#ifndef	OWP_PATH_SEPARATOR_LEN
#define	OWP_PATH_SEPARATOR_LEN	1
#endif
#ifndef	OWP_SESSIONS_DIR
#define	OWP_SESSIONS_DIR         "sessions"
#endif
#ifndef	OWP_NODES_DIR
#define	OWP_NODES_DIR            "nodes"
#endif
#ifndef	OWP_INCOMPLETE_EXT
#define	OWP_INCOMPLETE_EXT         ".i"
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <time.h>

#ifndef	False
#define	False	(0)
#endif
#ifndef	True
#define	True	(!False)
#endif

#ifndef MIN
#define MIN(a,b) ((a<b)?a:b)
#endif
#ifndef MAX
#define MAX(a,b) ((a>b)?a:b)
#endif

#include <owamp/rijndael-api-fst.h>
#include <owamp/arithm64.h>
#include <I2util/util.h>

#define	OWP_MODE_UNDEFINED		(0)
#define	OWP_MODE_OPEN			(01)
#define	OWP_MODE_AUTHENTICATED		(02)
#define	OWP_MODE_ENCRYPTED		(04)

/* Default mode offered by the server */
#define OWP_DEFAULT_OFFERED_MODE 	(OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/*
 * The 5555 should eventually be replaced by a IANA blessed service name.
 */
#define OWP_CONTROL_SERVICE_NAME	"5555"

/*
 * Default value to use for the listen backlog. We pick something large
 * and let the OS truncate it if it isn't willing to do that much.
 */
#define OWP_LISTEN_BACKLOG	(64)

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct OWPContextRec	*OWPContext;
typedef struct OWPControlRec	*OWPControl;
typedef struct OWPAddrRec	*OWPAddr;

/* Codes for returning error severity and type. */
/* values are mapped to syslog "priorities" we want to use. */
typedef enum {
	OWPErrFATAL=3,
	OWPErrWARNING=4,
	OWPErrINFO=6,
	OWPErrDEBUG=7,
	OWPErrOK=8
} OWPErrSeverity;

typedef enum {
	OWPErrUNKNOWN=0,
	OWPErrPOLICY,
	OWPErrINVALID,
	OWPErrUNSUPPORTED
} OWPErrType;

/*
 * Notice that this macro expands to multiple statements so it is
 * imperative that you enclose it's use in {} in single statement
 * context's such as:
 * 	if(test)
 * 		OWPError(...);	NO,NO,NO,NO!
 * Instead:
 * 	if(test){
 * 		OWPError(...);
 * 	}
 *
 *
 * (Sure would be nice if it were possible to to vararg macros...)
 */
#define OWPError	I2ErrLocation_(__FILE__,__DATE__,__LINE__);	\
			OWPError_

/*
 * Don't call this directly - use the OWPError macro.
 */
extern void
OWPError_(
	OWPContext	ctx,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*fmt,
	...
	);


/*
 * Valid values for "accept" - this will be added to for the purpose of
 * enumerating the reasons for rejecting a session, or early termination
 * of a test session.
 *
 * TODO:Get the additional "accept" values added to the spec.
 */
typedef enum{
	OWP_CNTRL_INVALID=-1,
	OWP_CNTRL_ACCEPT=0x0,
	OWP_CNTRL_REJECT=0x1,
	OWP_CNTRL_FAILURE=0x2,
	OWP_CNTRL_UNSUPPORTED=0x4
} OWPAcceptType;

typedef u_int32_t	OWPBoolean;
typedef u_int8_t	OWPSID[16];
typedef u_int8_t	OWPSequence[4];
typedef u_int8_t	OWPKey[16];
typedef u_int32_t	OWPSessionMode;

typedef struct OWPTimeStampRec{
	u_int32_t		sec;
	u_int32_t		frac_sec;
	u_int8_t		sync;
	u_int8_t		prec;
} OWPTimeStamp;


typedef enum {
	OWPTestUnspecified,	/* invalid value	*/
	OWPTestPoisson
} OWPTestType;

typedef struct{
	OWPTestType	test_type;
	OWPTimeStamp	start_time;
	u_int32_t	npackets;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
	u_int32_t	InvLambda;
} OWPTestSpecPoisson;

typedef struct{
	OWPTestType	test_type;
	OWPTimeStamp	start_time;
	u_int32_t	npackets;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
} OWPTestSpecAny;

typedef union _OWPTestSpec{
	OWPTestType		test_type;
	OWPTestSpecAny		any;
	OWPTestSpecPoisson	poisson;
	u_int32_t		padding[10]; /* bigger than any test... */
} OWPTestSpec;

/*
 * The following types are used to initialize the library.
 */

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 * It should return True if it is able to fill in the key_ret variable that
 * is passed in from the caller. False if not. If the function returns false,
 * the caller will check the err_ret value. If OK, then the kid simply didn't
 * exist - otherwise it indicates an error in the key store mechanism.
 */	
typedef OWPBoolean	(*OWPGetAESKeyFunc)(
	void		*app_data,
	const char	*kid,
	u_int8_t	*key_ret,
	OWPErrSeverity	*err_ret
);

/*
 * This function will be called from OWPControlOpen and OWPServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the kid.
 * On failure, value of *err_ret can be inspected: if > OWPErrWARNING,
 * this means rejection based on policy, otherwise there was an error
 * in the function itself.
 */
typedef OWPBoolean (*OWPCheckControlPolicyFunc)(
	OWPControl	cntrl,
	void		*app_data,
	OWPSessionMode	mode_req,
	const char	*kid,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	OWPErrSeverity	*err_ret
);

/*
 * This function will be called by OWPRequestTestSession if
 * one of the endpoints of the test is on the localhost before
 * it calls the EndpointInit*Func's. If err_ret returns
 * OWPErrFATAL, OWPRequestTestSession will not continue, and return
 * OWPErrFATAL as well.
 *
 * endpoint->sid will not be valid yet.
 * Only the IP address values will be set in the sockaddr structures -
 * i.e. port numbers will not be valid.
 */
typedef OWPBoolean (*OWPCheckTestPolicyFunc)(
	void		*app_data,
	OWPSessionMode	mode,
	const char	*kid,
	OWPBoolean	local_sender,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	OWPTestSpec	*test_spec,
	OWPErrSeverity	*err_ret
);

/*
 * The endpoint_handle data returned from this function is used by the
 * application to keep track of a particular endpoint of an OWAMP test.
 * It is opaque from the point of view of the library.
 * (It is simply a more specific app_data.)
 *
 * This function needs to allocate port and return it in the localsaddr
 * structure.
 * If "recv" - (send == False) then also allocate and return sid.
 */
typedef OWPErrSeverity (*OWPEndpointInitFunc)(
	void		*app_data,
	void		**end_data_ret,
	OWPBoolean	send,
	OWPAddr		localaddr,
	OWPTestSpec	*test_spec,
	OWPSID		sid_ret,	/* only used if !send */
	int		fd		/* only used if !send */
);

/*
 * Given remote_addr/port (can "connect" to remote addr now)
 * return OK
 * set the sid (if this is a recv - MUST be the same as came from Initfunc)
 */
typedef OWPErrSeverity (*OWPEndpointInitHookFunc)(
	void		*app_data,
	void		**end_data,
	OWPAddr		remoteaddr,
	OWPSID		sid
);

/*
 * Given start session
 */
typedef OWPErrSeverity (*OWPEndpointStartFunc)(
	void		*app_data,
	void		**end_data
);

/*
 * Get status of session
 */
typedef OWPErrSeverity (*OWPEndpointStatusFunc)(
	void		*app_data,
	void		**end_data,
	OWPAcceptType	*aval
);

/*
 * Given stop session
 */
typedef OWPErrSeverity (*OWPEndpointStopFunc)(
	void		*app_data,
	void		**end_data,
	OWPAcceptType	aval
);

/*
 * Given retrieve session
 */
typedef void (*OWPRetrieveSessionDataFunc)(
	void		*app_data,
	OWPSID		sid,
	OWPErrSeverity	*err_ret
);

/* 
 * This structure encodes parameters needed to initialize the library.
 */ 
typedef struct {
	struct timeval			tm_out;
	I2ErrHandle                     eh;
	OWPGetAESKeyFunc		get_aes_key_func;
	OWPCheckControlPolicyFunc	check_control_func;
	OWPCheckTestPolicyFunc		check_test_func;
	OWPEndpointInitFunc		endpoint_init_func;
	OWPEndpointInitHookFunc		endpoint_init_hook_func;
	OWPEndpointStartFunc		endpoint_start_func;
	OWPEndpointStatusFunc		endpoint_status_func;
	OWPEndpointStopFunc		endpoint_stop_func;
	int                             rand_type;
	void*                           rand_data;
} OWPInitializeConfigRec, *OWPInitializeConfig;

/*
 * API Functions
 *
 */
extern OWPContext
OWPContextInitialize(
	OWPInitializeConfig	config
);

extern void
OWPContextFree(
	OWPContext	ctx
);

/*
 * The OWPAddrBy* functions are used to allow the OWP API to more
 * adequately manage the memory associated with the many different ways
 * of specifying an address - and to provide a uniform way to specify an
 * address to the main API functions.
 * These functions return NULL on failure. (They call the error handler
 * to specify the reason.)
 */
extern OWPAddr
OWPAddrByNode(
	OWPContext	ctx,
	const char	*node	/* dns or valid char representation of addr */
);

extern OWPAddr
OWPAddrByAddrInfo(
	OWPContext		ctx,
	const struct addrinfo	*ai	/* valid addrinfo linked list	*/
);

extern OWPAddr
OWPAddrBySockFD(
	OWPContext	ctx,
	int		fd	/* fd must be an already connected socket */
);

/*
 * Return the address for the local side of the control connection.
 * (getsockname)
 */
OWPAddr
OWPAddrByLocalControl(
	OWPControl cntrl
	);

void
OWPAddr2string(OWPAddr addr, char *buf, size_t len);

/*
 * return FD for given OWPAddr or -1 if it doesn't refer to a socket yet.
 */
extern int
OWPAddrFD(
	OWPAddr	addr
	);

/*
 * return socket address length (for use in calling accept etc...)
 * or 0 if it doesn't refer to a socket yet.
 */
extern socklen_t
OWPAddrSockLen(
	OWPAddr	addr
	);

extern OWPErrSeverity
OWPAddrFree(
	OWPAddr	addr
);

/*
 * OWPControlOpen allocates an OWPclient structure, opens a connection to
 * the OWP server and goes through the initialization phase of the
 * connection. This includes AES/CBC negotiation. It returns after receiving
 * the ServerOK message.
 *
 * This is typically only used by an OWP client application (or a server
 * when acting as a client of another OWP server).
 *
 * err_ret values:
 * 	OWPErrOK	completely successful - highest level mode ok'd
 * 	OWPErrINFO	session connected with less than highest level mode
 * 	OWPErrWARNING	session connected but future problems possible
 * 	OWPErrFATAL	function will return NULL - connection is closed.
 * 		(Errors will have been reported through the OWPErrFunc
 * 		in all cases.)
 * function return values:
 * 	If successful - even marginally - a valid OWPclient handle
 * 	is returned. If unsuccessful, NULL is returned.
 *
 * local_addr can only be set using OWPAddrByNode or OWPAddrByAddrInfo
 * server_addr can use any of the OWPAddrBy* functions.
 *
 * Once an OWPAddr record is passed into this function - it is
 * automatically free'd and should not be referenced again in any way.
 *
 * Client
 */
extern OWPControl
OWPControlOpen(
	OWPContext	ctx,
	OWPAddr		local_addr,	/* src addr or NULL		*/
	OWPAddr		server_addr,	/* server addr or NULL		*/
	u_int32_t	mode_mask,	/* OR of OWPSessionMode vals	*/
	const char	*kid,		/* null if unwanted		*/
	void		*app_data,	/* set app_data	for connection	*/
	OWPErrSeverity	*err_ret
);

/*
 * Client and Server
 */
extern OWPErrSeverity
OWPControlClose(
	OWPControl	cntrl
);

/*
 * Request a test session - if err_ret is OWPErrOK - then the function
 * returns a valid SID for the session.
 *
 * Once an OWPAddr record has been passed into this function, it
 * is automatically free'd. It should not be referenced again in any way.
 *
 * Client
 */
extern OWPBoolean
OWPSessionRequest(
	OWPControl	control_handle,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	OWPSID		sid_ret,
	int		fd,	/* only used if !server_conf_receiver */
	OWPErrSeverity	*err_ret
);

/*
 * Start all test sessions - if successful, returns OWPErrOK.
 *
 * Client and Server
 */
extern OWPErrSeverity
OWPStartSessions(
	OWPControl	control_handle
);

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 * 	<0	ErrorCondition
 * 	0	StopSessions received, acted upon, and sent back.
 * 	1	wake_time reached
 *	2	system event (signal)
 *
 * To effect a poll - specify a waketime in the past. 1 will be returned
 * if there is nothing to read.
 *
 * To block indefinately, specify a NULL wake_time. (StopSessionsWait will
 * poll the status of current tests automatically whenever a system event
 * takes place in this case, so StopSessionsWait will never return 1 or 2
 * in this case.)
 *
 * If you do specify a wake time, you are required to poll the status
 * of each local endpoint using OWPTestSessionStatus until it comes back
 * complete.  (OWPSessionsActive is a simple way to poll all of them - you
 * know you are done when it returns 0.)
 *
 * Client and Server
 */
extern int
OWPStopSessionsWait(
	OWPControl	control_handle,
	OWPTimeStamp	*wake_time,		/* abs time */
	OWPAcceptType	*acceptval,		/* out */
	OWPErrSeverity	*err_ret
);

/*
 * Used to poll the status of a test endpoint.
 *
 * returns:
 * 		True if it could get the status,
 * 		False if it could not. (session with given sid wasn't found,
 * 		or "send" indicated a remote endpoint.)
 *
 * 		aval returns the following for status:
 * 	<0	Test is not yet complete.
 * 	>=0	Accept value of completed test. 0 indicates success
 * 		other values indicate type of error test encountered.
 */
extern OWPBoolean
OWPSessionStatus(
	OWPControl	cntrl,
	OWPSID		sid,	/* SID of test to poll	*/
	OWPBoolean	send,	/* Poll the send side of the test if true*/
				/* recv side if false			*/
	OWPAcceptType	*aval	/* out - return accept value	*/
	);

/*
 * Used to determine how many local endpoints are still active.
 * (effectively calls the OWPTestSessionStatus function on all endpoints
 * and determines if they are complete yet.)
 *
 * returns:
 * 	number of active endpoints.
 */
extern int
OWPSessionsActive(
		OWPControl	cntrl
		);

/*
 * Send the StopSession message, and wait for the response.
 *
 * Client and Server.
 */
extern OWPErrSeverity
OWPStopSessions(
	OWPControl	control_handle,
	OWPAcceptType	*acceptval	/* in/out */
);


/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the OWPStopSessionsWait
 * function so that the application can recieve user input, and only call
 * the OWPStopSessionsWait function when there is something to read
 * from the connection. (A nul timestamp would be used in this case
 * so that OWPStopSessionsWait does not block.)
 *
 * If the control_handle is no longer connected - the function will return
 * a negative value.
 *
 * Client and Server.
 */
extern int
OWPControlFD(
	OWPControl	control_handle
);

extern int
OWPErrorFD(
	OWPContext	ctx
	);

extern
OWPAddr
OWPServerSockCreate(
	OWPContext	ctx,
	OWPAddr		addr,
	OWPErrSeverity	*err_ret
	);


/*!
 * Function:	OWPControlAccept
 *
 * Description:	
 * 		This function is used to initialiize the communication
 * 		to the peer.
 *           
 * In Args:	
 * 		connfd,connsaddr, and connsaddrlen are all returned
 * 		from "accept".
 *
 * Returns:	Valid OWPControl handle on success, NULL if
 *              the request has been rejected, or error has occurred.
 *              Return value does not distinguish between illegal
 *              requests, those rejected on policy reasons, or
 *              errors encountered by the server during execution.
 * 
 * Side Effect:
 */
extern OWPControl
OWPControlAccept(
	OWPContext	ctx,		/* library context		*/
	int		connfd,		/* conencted socket		*/
	struct sockaddr	*connsaddr,	/* connected socket addr	*/
	socklen_t	connsaddrlen,	/* connected socket addr len	*/
	u_int32_t	mode_offered,	/* advertised server mode	*/
	void		*app_data,	/* set app_data for conn	*/
	OWPErrSeverity	*err_ret	/* err - return			*/
		 );


extern OWPErrSeverity
OWPProcessTestRequest(
	OWPControl	cntrl
		);

extern OWPErrSeverity
OWPProcessStartSessions(
	OWPControl	cntrl
	);

extern OWPErrSeverity
OWPProcessStopSessions(
	OWPControl	cntrl
	);

extern OWPErrSeverity
OWPProcessRetrieveSession(
	OWPControl	cntrl
	);

/*
 * TODO: Add timeout so ProcessRequests can break out if no request
 * comes in some configurable fixed time. (Necessary to have the server
 * process exit when test sessions are done, if the client doesn't send
 * the StopSessions.)
 */
extern OWPErrSeverity
OWPProcessRequests(
	OWPControl	cntrl
		);

/*
** Fetch context field of OWPControl structure.
*/
extern OWPContext
OWPGetContext(
	OWPControl	cntrl
	);

extern OWPSessionMode
OWPGetMode(
	OWPControl	cntrl
	);

extern keyInstance*
OWPGetAESkeyInstance(
		OWPControl	cntrl,
		int		which
		);

typedef u_int32_t OWPPacketSizeT;

/*
** Given the protocol family, OWAMP mode and packet padding,
** compute the size of resulting full IP test packet.
*/
OWPPacketSizeT OWPTestPayloadSize(
		int		mode,
		u_int32_t	padding
		);
OWPPacketSizeT OWPTestPacketSize(
		int		af,
		int		mode,
		u_int32_t	padding
		);

/*
** Applications use this type to manipulate timestamp data records.
*/
typedef struct OWPCookedDataRec {
	u_int32_t    seq_no;
	OWPTimeStamp send;
	OWPTimeStamp recv;
} OWPCookedDataRec, *OWPCookedDataRecPtr;

/*
** This (type of) function is used by Fetch-Client to process (cooked)
** data records. 
*/
typedef int (*OWPDoDataRecord)(
			       void                *calldata,
			       OWPCookedDataRecPtr rec
			       );

OWPErrSeverity
OWPFetchSessionInfo(OWPControl cntrl,
		    u_int32_t  begin,
		    u_int32_t  end,
		    OWPSID     sid,
		    u_int32_t  *num_rec,
		    u_int8_t  *typeP
		    );

OWPErrSeverity
OWPWriteDataHeader(OWPControl cntrl, int fd, u_int8_t *typeP);

/*
** Read the promised number of records 
** and write them to the provided file descriptor <fd>. Return OWPErrOK
** on success, or OWPErrFATAL on failure.
*/
OWPErrSeverity
OWPFetchRecords(OWPControl cntrl, int fd, u_int32_t num_rec);

OWPErrSeverity
OWPReadDataHeader(int fd, u_int32_t *typeP);

/*
** "Fetching" data from local disk.
*/
OWPErrSeverity
OWPFetchLocalRecords(int fd, 
		     u_int32_t num_rec, 
		     OWPDoDataRecord proc_rec,
		     void *app_data);

/*
** Read the final 16 bytes of data stream and make sure it's all zeros.
*/
OWPErrSeverity
OWPCheckPadding(OWPControl cntrl);

/*
** Compute delay between send time and receive time.
*/
double
owp_delay(OWPTimeStamp *send_time, OWPTimeStamp *recv_time);

/*
** Given a 20-byte timestamp record, return its sequence number.
*/
u_int32_t
OWPGetSeqno(u_int8_t *rec);

/*
** Parse the 20-byte timestamp data record for application to use.
*/
void
OWPParseDataRecord(u_int8_t *rec, 
		   OWPTimeStamp *send, 
		   OWPTimeStamp *recv, 
		   u_int32_t     *seq_no);

/*
 * buff must be at least (nbytes*2) +1 long or memory will be over-run.
 */
void
OWPHexEncode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	);

void
OWPHexDecode(
	char		*buff,
	u_int8_t	*bytes,
	unsigned int	nbytes
	);

/*
 * time.c conversion functions.
 */

#define	OWPJAN_1970	(unsigned long)0x83aa7e80	/* diffs in epoch*/

extern OWPTimeStamp *
OWPCvtTimeval2Timestamp(
	OWPTimeStamp	*tstamp,
	struct timeval	*tval
);

extern struct timeval *
OWPCvtTimestamp2Timeval(
	struct timeval	*tval,
	OWPTimeStamp	*tstamp
	);


extern OWPTimeStamp *
OWPGetTimeOfDay(
	OWPTimeStamp	*tstamp
);

extern OWPTimeStamp *
OWPCvtTimespec2Timestamp(
	OWPTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest	/* usec's */
	);

extern struct timespec *
OWPCvtTimestamp2Timespec(
	struct timespec	*tval,
	OWPTimeStamp	*tstamp
	);

#endif	/* OWAMP_H */
