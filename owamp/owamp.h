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
#ifndef	OWP_FILE_EXT
#define	OWP_FILE_EXT	".owp"
#endif	/* OWP_FILE_EXT */

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

typedef struct OWPTimeStampRec{
	u_int32_t		sec;
	u_int32_t		frac_sec;
	u_int8_t		sync;
	u_int8_t		prec;
} OWPTimeStamp;

/*
 * This must be included after the definition of the TimeStamp.
 */
#include <owamp/arithm64.h>

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
	u_int32_t		padding[15]; /* bigger than any test... */
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
 * one of the endpoints of the test is on the localhost.
 * If err_ret returns OWPErrFATAL, OWPRequestTestSession/OWPProcessTestSession
 * will not continue, and return OWPErrFATAL as well.
 *
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
 * This structure encodes parameters needed to initialize the library.
 */ 
typedef struct {
	struct timeval			tm_out;	/* connect timeout for cntrl */
	I2ErrHandle                     eh;
	OWPGetAESKeyFunc		get_aes_key_func;
	OWPCheckControlPolicyFunc	check_control_func;
	OWPCheckTestPolicyFunc		check_test_func;
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
 * Request a test session - if the function returns True, then the function
 * returns a valid SID for the session.
 *
 * If the function returns False - check err_ret. If err_ret is ErrOK, the
 * session was denied by the server, and the control connection is still
 * valid.
 *
 * TODO:Add OWPControlStatus(cntrl) function to determine cntrl status...
 *
 * Reasons this function will return False:
 * 1. Server denied test: err_ret==ErrOK
 * 2. Control connection failure: err_ret == ErrFATAL
 * 3. Local resource problem (malloc/fork/fdopen): err_ret == ErrFATAL
 * 4. Bad addresses: err_ret == ErrWARNING
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
	FILE		*fp,		/* only used if !server_conf_receiver */
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
 * Returns the duration of the session in OWPnum64 format. Conversion
 * functions are available to convert that to OWPTimeStamp format.
 * 0 is returned for non-existant SID's.
 */
extern OWPnum64
OWPSessionDuration(
	OWPControl	cntrl,
	OWPSID		sid
	);

/*
 * Returns the schedule of the session as an array of OWPnum64's. These
 * OWPnum64's are offsets from the "start" time of the session. Also
 * care must be used because this function is not copying the memory, this
 * is the array being used internally by the library. It should be considered
 * READ ONLY. Also - the memory associated with this schedule is freed
 * when the session is officially over during the StopSessions or
 * StopSessionsWait functions.
 */
extern OWPnum64*
OWPSessionSchedule(
	OWPControl	cntrl,
	OWPSID		sid
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

extern struct timeval*
OWPGetDelay(
	OWPControl	cntrl,
	struct timeval	*tval
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
extern OWPPacketSizeT
OWPTestPayloadSize(
		int		mode,
		u_int32_t	padding
		);
extern OWPPacketSizeT
OWPTestPacketSize(
		int		af,
		int		mode,
		u_int32_t	padding
		);

/*
 * This data structure is used to read/write a session header. When
 * reading a header, if the "header" element returns false, the file
 * did not contain any header information, and the remaining fields
 * are not valid.
 */
typedef struct OWPSessionHeaderRec{
	OWPBoolean		header;
	u_int32_t		rec_size;
	OWPSID			sid;
	struct sockaddr_storage	addr_sender;
	struct sockaddr_storage	addr_receiver;
	OWPBoolean		conf_sender;
	OWPBoolean		conf_receiver;
	OWPTestSpec		test_spec;
} OWPSessionHeaderRec, *OWPSessionHeader;

/*
 * This function is used to request that the data for the TestSession
 * identified by sid be fetched from the server and copied to the
 * file pointed at by fp. This function assumes fp is currently pointing
 * at an open file, and that fp is ready to write at the begining of the file.
 * (If there are any file i/o errors it is currently treated as a hard
 * error and the cntrl connection is disabled.)
 *
 * To request an entire session set begin = 0, and end = 0xFFFFFFFF.
 *
 * TODO: In v5, this function should return interesting information about
 * the session in question.
 *
 * Returns: Number of records that were fetched.
 * 	0 indicates no records fetched - if err_ret is OK, then server
 * 	denied request and cntrl is still valid for other requests.
 */
extern int
OWPFetchSession(
	OWPControl		cntrl,
	FILE			*fp,
	u_int32_t		begin,
	u_int32_t		end,
	OWPSID			sid,
	OWPSessionHeader	hdr_ret,
	OWPErrSeverity		*err_ret
	);
/*
 * Write data header to the file. <len> is the length of the buffer - 
 * any other fields have to be accounted for separately in the
 * header length value.
 * Returns:
 * 0	Success
 */
int
OWPWriteDataHeader(
		OWPContext		ctx,
		FILE			*fp,
		OWPSessionHeader	hdr
		);

/*
 * Read data header from file. TODO: v5 .. more interesting.
 *
 * Returns:
 * number of records in the file. 0 on error. (errno will be set.)
 */
u_int32_t
OWPReadDataHeader(
		OWPContext		ctx,
		FILE			*fp,
		u_int32_t		*hdr_len,
		OWPSessionHeader	hdr_ret
		);

/*
** Processing Session data from local disk.
*/

/*
** Applications use this type to manipulate timestamp data records.
*/
typedef struct OWPDataRec {
	u_int32_t    seq_no;
	OWPTimeStamp send;
	OWPTimeStamp recv;
} OWPDataRec, *OWPDataRecPtr;

extern OWPBoolean
OWPIsLostRecord(
	OWPDataRecPtr	rec
	);

/*
 * This (type of) function is used by Fetch-Client to process
 * data records.
 *
 * The function should return < 0 to indicate an error condition in which
 * case OWPParseRecords will return OWPErrFATAL.
 * It should return 0 to continue parsing.
 * It should return 1 to terminate parsing in which case OWPParseRecords will
 * return OWPErrOK.
 *
 * num_rec can be any number less than or equal to the number of valid
 * records in the file reported by OWPReadDataHeader. This function assumes
 * the fp is currently pointing at the beginning of a data record.
 * (This can be done simply by calling OWPReadDataHeader or fseek'ing to
 * the offset reported by OWPReadDataHeader.) Or advancing by some multiple
 * of hdr.rec_size.
 *
 * If OWPParseRecords completes parsing "num_rec" records with out error,
 * it will return OWPErrOK.
 * If OWPParseRecords is unable to complete parsing because of file i/o problems
 * it will return OWPErrFATAL.
 */
typedef int (*OWPDoDataRecord)(
       void		*calldata,
       OWPDataRecPtr	rec
       );

OWPErrSeverity
OWPParseRecords(
	FILE			*fp,
	u_int32_t		num_rec, 
	OWPSessionHeader	hdr,
	OWPDoDataRecord		proc_rec,
	void			*app_data
	);

/*
** Compute delay between send time and receive time.
*/
double
owp_delay(OWPTimeStamp *send_time, OWPTimeStamp *recv_time);

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

#ifndef	tvalclear
#define	tvalclear(a)	(a)->tv_sec = (a)->tv_usec = 0
#endif
#ifndef	tvaladd
#define tvaladd(a,b)					\
	do{						\
		(a)->tv_sec += (b)->tv_sec;		\
		(a)->tv_usec += (b)->tv_usec;		\
		if((a)->tv_usec >= 1000000){		\
			(a)->tv_sec++;			\
			(a)->tv_usec -= 1000000;	\
		}					\
	} while (0)
#endif
#ifndef	tvalsub
#define tvalsub(a,b)					\
	do{						\
		(a)->tv_sec -= (b)->tv_sec;		\
		(a)->tv_usec -= (b)->tv_usec;		\
		if((a)->tv_usec < 0){			\
			(a)->tv_sec--;			\
			(a)->tv_usec += 1000000;	\
		}					\
	} while (0)
#endif

#ifndef	tvalcmp
#define	tvalcmp(tvp,uvp,cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?			\
	 	((tvp)->tv_usec cmp (uvp)->tv_usec) :		\
		((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

/* Operations on timespecs */
#ifndef	timespecclear
#define timespecclear(tvp)      ((tvp)->tv_sec = (tvp)->tv_nsec = 0)
#endif

#ifndef	timespecisset
#define timespecisset(tvp)      ((tvp)->tv_sec || (tvp)->tv_nsec)
#endif

#ifndef	timespeccmp
#define timespeccmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
		((tvp)->tv_nsec cmp (uvp)->tv_nsec) :			\
		((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#ifndef	timespecadd
#define timespecadd(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec += (uvp)->tv_sec;				\
		(vvp)->tv_nsec += (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec >= 1000000000){			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_nsec -= 1000000000;			\
		}							\
	} while (0)
#endif

#ifndef timespecsub
#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
#endif

#ifndef	timespecdiff
#define	timespecdiff(vvp,uvp)						\
	do {								\
		struct timespec	ts1_,ts2_;				\
		if(timespeccmp(vvp,uvp,>)){				\
			ts1_ = *vvp;					\
			ts2_ = *uvp;					\
		}else{							\
			ts1_ = *uvp;					\
			ts2_ = *vvp;					\
		}							\
		timespecsub(&ts1_,&ts2_);				\
		*vvp = ts1_;						\
	} while(0)
#endif

#ifndef	OWPTimeStampCmp
#define	OWPTimeStampCmp(tvp,uvp,cmp)					\
	(((tvp)->sec == (uvp)->sec) ?					\
		((tvp)->frac_sec cmp (uvp)->frac_sec) :			\
		((tvp)->sec cmp (uvp)->sec))
#endif

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

extern double
owp_bits2prec(int nbits);

double
OWPPrecision(OWPDataRecPtr rec);

u_int8_t
OWPGetPrecBits(OWPDataRecPtr rec);

#endif	/* OWAMP_H */
