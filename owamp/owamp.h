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

#include <I2util/util.h>

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

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

#if	defined HAVE_DECL_FSEEKO && !HAVE_DECL_FSEEKO
#define fseeko(a,b,c) fseek(a,b,c)
#endif

#include <limits.h>
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

/*
 * Filename/path component macros used by various parts of owamp.
 */
#ifndef OWP_PATH_SEPARATOR
#define	OWP_PATH_SEPARATOR	"/"
#endif
#ifndef	OWP_PATH_SEPARATOR_LEN
#define	OWP_PATH_SEPARATOR_LEN	1
#endif
#ifndef	OWP_FILE_EXT
#define	OWP_FILE_EXT	".owp"
#endif

/*
 * The ascii decimal encoding of the 64 bit timestamps takes this many
 * chars. Log(2^64)
 *
 * fmt indicates 0 padding, 20 significant digits.
 */
#ifndef OWP_TSTAMPFMT 
#define OWP_TSTAMPFMT  "%020llu"
#endif

#ifndef OWP_TSTAMPCHARS
#define OWP_TSTAMPCHARS  20
#endif

/*
 * Char used between start_end.owp files.
 */
#ifndef OWP_NAME_SEP
#define OWP_NAME_SEP    "_"
#endif


#include <owamp/rijndael-api-fst.h>

/* Default mode offered by the server */
#define OWP_DEFAULT_OFFERED_MODE 	(OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/*
 * TODO: 4822 should eventually be replaced by an IANA blessed service name.
 */
#define OWP_CONTROL_SERVICE_NAME	"4822"

/*
 * Default value to use for the listen backlog. We pick something large
 * and let the OS truncate it if it isn't willing to do that much.
 */
#define OWP_LISTEN_BACKLOG	(64)

/*
 * OWPNum64 is interpreted as 32bits of "seconds" and 32bits of
 * "fractional seconds".
 * The byte ordering is defined by the hardware for this value. 4 MSBytes are
 * seconds, 4 LSBytes are fractional. Each set of 4 Bytes is pulled out
 * via shifts/masks as a 32bit unsigned int when needed independently.
 *
 * sync/multiplier/scale are defined as in Section 5.1 of
 * draft-ietf-ippm-owdp-05.txt:
 * If sync is non-zero, then the party generating the timestamp claims to
 * have an external source of synchronization to UTC.
 * multiplier and scale are used to indicate the estimated error of
 * owptime.
 * They are interpreted as follows:
 * multiplier*(2^(-32))*(2^Scale)
 *
 * (implementor note)
 * Effectively, this breaks down such that if Scale is 0, then the multiplier
 * is the error in the same scale as the fractional seconds of owptime.
 * Therefore, for "real" errors greater than an 8 bit number at that scale
 * the value can just be right shifted until it fits into an 8 bit integer,
 * and the number of shifts would indicate the "Scale" value.
 */
typedef u_int64_t OWPNum64;

/*
 * Arithmetic/Conversion functions on OWPNum64 numbers.
 */

/*
 * These macros should be used instead of directly using
 * arithmetic on these types in the event that the underlying
 * type is changed from an u_int64_t to some kind of structure.
 *
 */
#define OWPNum64Diff(x,y)	((x>y) ? (x-y) : (y-x))
#define OWPNum64Add(x,y)	(x+y)
#define OWPNum64Sub(x,y)	(x-y)
#define OWPNum64Cmp(x,y)	((x<y) ? -1 : ((x>y) ? 1 : 0))

extern OWPNum64
OWPNum64Mult(
	OWPNum64	x,
	OWPNum64	y
	);

extern OWPNum64
OWPULongToNum64(
	u_int32_t	from);


extern void
OWPNum64ToTimeval(
	struct timeval	*to,
	OWPNum64	from
	);

extern void
OWPTimevalToNum64(
	OWPNum64	*to,
	struct timeval	*from
	);

extern void
OWPNum64ToTimespec(
	struct timespec	*to,
	OWPNum64	from
	);

extern void
OWPTimespecToNum64(
	OWPNum64	*to,
	struct timespec	*from
	);

extern double
OWPNum64ToDouble(
	OWPNum64	from
	);

extern OWPNum64
OWPDoubleToNum64(
	double		from
	);

extern OWPNum64
OWPUsecToNum64(u_int32_t usec);

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct OWPContextRec	*OWPContext;
typedef struct OWPControlRec	*OWPControl;
typedef struct OWPAddrRec	*OWPAddr;

/*
 * Timestamp related types and structures needed throughout.
 */

typedef struct OWPTimeStampRec{
	OWPNum64		owptime;
	u_int8_t		sync;
	u_int8_t		multiplier;
	u_int8_t		scale;
} OWPTimeStamp;


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

/*
 * technically the username in the client greeting message can have u_int8_t
 * but this implementation limits it to a valid "char" type.
 */
#define	OWP_USERID_LEN	16
typedef char		OWPUserID[OWP_USERID_LEN+1];	/* add 1 for '\0' */
typedef u_int8_t	OWPKey[16];

#define	OWP_MODE_UNDEFINED		(0)
#define	OWP_MODE_OPEN			(01)
#define	OWP_MODE_AUTHENTICATED		(02)
#define	OWP_MODE_ENCRYPTED		(04)
#define	OWP_MODE_DOCIPHER	(OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

typedef u_int32_t	OWPSessionMode;

typedef enum {
	OWPSlotUnspecifiedType = -1,	/* invalid value	*/
	OWPSlotRandExpType = 0,
	OWPSlotLiteralType = 1
} OWPSlotType;

typedef struct{
	OWPSlotType	slot_type;
	OWPNum64	mean;
} OWPSlotRandExp;

typedef struct{
	OWPSlotType	slot_type;
	OWPNum64	offset;
} OWPSlotLiteral;

/*
 * For now - all current slot types are of the exact same format, and
 * the "time" element can be interpreted as the mean_delay between packets
 * for the purposes of bandwidth calculations. If that is ever not true,
 * this type should be removed, and any code that uses it will need to
 * have a switch statement to do whatever is appropriate for each individual
 * slot type.
 */
typedef struct{
	OWPSlotType	slot_type;
	OWPNum64	mean_delay;
} OWPSlotAny;

typedef union OWPSlotUnion{
	OWPSlotType	slot_type;
	OWPSlotRandExp	rand_exp;
	OWPSlotLiteral	literal;
	OWPSlotAny	any;
} OWPSlot;

typedef struct{
	OWPNum64	start_time;
	OWPNum64	loss_timeout;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
	u_int32_t	npackets;
	u_int32_t	nslots;
	OWPSlot		*slots;
} OWPTestSpec;

typedef u_int32_t OWPPacketSizeT;

/*
 * an OWPScheduleContextRec is used to maintain state for the schedule
 * generator. Multiple contexts can be allocated to maintain multiple
 * "streams" of schedules.
 */
typedef struct OWPScheduleContextRec	*OWPScheduleContext;

OWPScheduleContext
OWPScheduleContextCreate(
		OWPContext	ctx,
		OWPSID		sid,
		OWPTestSpec	*tspec
		);

void
OWPScheduleContextFree(
	OWPScheduleContext	sctx
		);

OWPErrSeverity
OWPScheduleContextReset(
	OWPScheduleContext	sctx,
		OWPSID		sid,
		OWPTestSpec	*tspec
		);

OWPNum64
OWPScheduleContextGenerateNextDelta(
	OWPScheduleContext	sctx
		);
void
OWPScheduleContextFree(
	OWPScheduleContext	sctx
		);

/*
 * These functions expose the exponential deviates for the exponential
 * distribution used to generate send schedules.
 */
typedef struct OWPExpContextRec		*OWPExpContext;

OWPExpContext
OWPExpContextCreate(
		OWPContext	ctx,
		u_int8_t	seed[16]
		);
OWPNum64
OWPExpContextNext(
		OWPExpContext	exp
		);

void
OWPExpContextFree(
		OWPExpContext	exp
		);


/*
 * Error Reporting:
 *
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
 * 	Let me repeat.
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
 * The "context"  is used to basically initializes the library. There is no
 * "global" state - so you can create more than one "context" if you like.
 * (Well... SIGPIPE is disabled... I suppose that is global.)
 *
 * There are specific defaults that can be modified within the context by
 * calling the OWPContextConfigSet function with the following keys and
 * types. (The key is a string - the type indicates what type of data
 * will be stored/retrieved using that key.
 */

/*
 * This type is used to hold a pointer to an integer pointer. That pointer
 * points at a value that determines if the low/level i/o functions should
 * return on interrupt. If it is non-zero an interrupt will cause the i/o
 * routine to fail and return. If it is zero, the low level i/o routine will
 * ignore the interrupt and restart the i/o.
 * (this can be used to ignore some signals and return on others.)
 */
#define OWPInterruptIO		"OWPInterruptIO"

/*
 * This type is used to hold a pointer to a port-range record. This
 * record is used to indicate what port ranges should be used for
 * opening test connections.
 */
#define	OWPTestPortRange	"OWPTestPortRange"
typedef	struct OWPPortRangeRec{
	u_int16_t	low;
	u_int16_t	high;
} OWPPortRangeRec, *OWPPortRange;

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 * It should return True if it is able to fill in the key_ret variable that
 * is passed in from the caller. False if not. If the function returns false,
 * the caller should check the err_ret value. If OK, then the userid simply
 * didn't exist - otherwise it indicates an error in the key store mechanism.
 *
 * If an application doesn't set this, Encrypted and Authenticated
 * mode will be disabled.
 */	
#define	OWPGetAESKey		"OWPGetAESKey"
typedef OWPBoolean	(*OWPGetAESKeyFunc)(
	OWPContext	ctx,
	const OWPUserID	userid,
	OWPKey		key_ret,
	OWPErrSeverity	*err_ret
);

/*
 * This function will be called from OWPControlOpen and OWPServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the userid.
 * On failure, value of *err_ret can be inspected: if > OWPErrWARNING,
 * this means rejection based on policy, otherwise there was an error
 * in the function itself.
 *
 * If an application doesn't set this, all connections will be allowed.
 */
#define OWPCheckControlPolicy	"OWPCheckControlPolicy"
typedef OWPBoolean (*OWPCheckControlPolicyFunc)(
	OWPControl	cntrl,
	OWPSessionMode	mode_req,
	const OWPUserID	userid,
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
 *
 * If an application doesn't set this, all tests will be allowed.
 *
 * The application can use the "closure" pointer to store data that will
 * be passed onto the Open/Close and TestComplete functions. The intended
 * purpose of this pointer is to keep track of resources that are "reserved"
 * from this function - allowing the other functions to "free" or modify
 * those resource reservations.
 *
 * NOTE: Even if the application does not use the "closure" pointer to keep
 * track of resources - it should set the closure to a non-NULL value upon
 * return so the OpenFile function knows the file is being opened for
 * writing (a receiver context) and not being opened for reading (a fetch
 * context).
 */
#define OWPCheckTestPolicy	"OWPCheckTestPolicy"
typedef OWPBoolean (*OWPCheckTestPolicyFunc)(
	OWPControl	cntrl,
	OWPBoolean	local_sender,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	socklen_t	sa_len,
	OWPTestSpec	*test_spec,
	void		**closure,
	OWPErrSeverity	*err_ret
);

/*
 * This function will be called when a test is "complete". It is used
 * to free resources that were allocated on behalf of the test including
 * memory associated with the "closure" pointer itself if necessary.
 */
#define OWPTestComplete		"OWPTestComplete"
typedef void (*OWPTestCompleteFunc)(
	OWPControl	cntrl,
	void		*closure,
	OWPAcceptType	aval
	);

/*
 * This function will be called by the test endpoint initialization
 * code to open a file for writing. It will also be called by the
 * fetch-session code to open an existing file to return the data
 * to an application. (fname_ret is PATH_MAX+1 to include a nul byte.)
 * (if 
 */
#define OWPOpenFile		"OWPOpenFile"
typedef FILE* (*OWPOpenFileFunc)(
	OWPControl	cntrl,
	void		*closure,
	OWPSID		sid,
	char		fname_ret[PATH_MAX+1]
	);

/*
 * This function will be called by the test endpoint "cleanup" code
 * to indicate that the given fp (from OWPOpenFile) is no longer needed.
 * This allows the implementation to do it's own cleanup based on policy.
 * For example, a delete-on-fetch functionality could be implemented here
 * to delete the given file now that is it no longer needed.
 */
#define OWPCloseFile		"OWPCloseFile"
typedef void (*OWPCloseFileFunc)(
	OWPControl	cntrl,
	void		*closure,
	FILE		*fp,
	OWPAcceptType	aval
	);

#ifndef	NDEBUG
/*
 * This integer type is used to aid in child-debugging. If OWPChildWait is
 * set and non-zero forked off endpoints will go into a busy-wait loop to
 * allow a debugger to attach to the process. (i.e. they will be hung until
 * attached and the loop variable modified with the debugger. This should
 * not strictly be needed, but the gdb on many of the test plateforms I
 * used did not implement the follow-fork-mode option.) This was a quick
 * fix. (This will not be used if owamp is compiled with -DNDEBUG.)
 */
#define	OWPChildWait	"OWPChildWait"
#endif

extern OWPContext
OWPContextCreate(
	I2ErrHandle	eh
);

extern void
OWPContextFree(
	OWPContext	ctx
);

extern I2ErrHandle
OWPContextGetErrHandle(
	OWPContext	ctx
	);

extern OWPBoolean
OWPContextConfigSet(
	OWPContext	ctx,
	const char	*key,
	void		*value
	);

extern void*
OWPContextConfigGet(
	OWPContext	ctx,
	const char	*key
	);

extern OWPBoolean
OWPContextConfigDelete(
	OWPContext	ctx,
	const char	*key
	);

/*
 * The following functions are completely analogous to the Context versions
 * but are used to maintain state information about a particular control
 * connection.
 */
extern OWPBoolean
OWPControlConfigSet(
	OWPControl	cntrl,
	const char	*key,
	void		*value
	);

extern void*
OWPControlConfigGet(
	OWPControl	cntrl,
	const char	*key
	);

extern OWPBoolean
OWPControlConfigDelete(
	OWPControl	cntrl,
	const char	*key
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
OWPAddrNodeName(
	OWPAddr	addr,
	char	*buf,
	size_t	*len	/* in/out parameter for buf len */
	);

void
OWPAddrNodeService(
	OWPAddr	addr,
	char	*buf,
	size_t	*len	/* in/out parameter for buf len */
	);

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
	OWPUserID	userid,		/* null if unwanted		*/
	OWPNum64	*uptime_ret,	/* server uptime - ret or NULL	*/
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
 * Conversely, the test_spec is completely copied, and the caller continues
 * to "own" all memory associated with it after this call. (Including
 * the "slots" array that is part of the test_spec.)
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
	FILE		*fp,		/* only used if !server_conf_receiver */
	OWPSID		sid_ret,
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
 *
 *	2	system event (signal)
 *
 * To effect a poll - specify a waketime in the past. 1 will be returned
 * if there is nothing to read.
 *
 * To use a signal interaction instead of the waketime interface, set the
 * retn_on_intr pointer. Install a signal handler that sets the value
 * to non-zero, and this function will return 2. (If wake_time is non-null,
 * retn_on_intr is not used.) This interface can be used without signal
 * handlers as well be simply passing in a pointer to a non-zero value.
 * This function will return for any interrupt. (The signal interface
 * allows you to set the value to non-zero only for signals you are
 * actually interested in.)
 *
 * To block indefinately, specify NULL for wake_time and NULL for
 * retn_on_intr. (StopSessionsWait will poll the status of current tests
 * automatically whenever a system event takes place in this case, so
 * StopSessionsWait will never return 1 or 2 in this case.)
 *
 * If wake_time or retn_on_intr is set, and this function returns 1 or 2, then
 * it is required to poll the status of each local endpoint using
 * OWPTestSessionStatus until all sessions complete.  (OWPSessionsActive is
 * a simple way to poll all of them - you know you are done when it returns 0.)
 * You can of course recall StopSessionsWait in this case.
 *
 * Client and Server
 */
extern int
OWPStopSessionsWait(
	OWPControl	control_handle,
	OWPNum64	*wake_time,		/* abs time */
	int		*retn_on_intr,
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
	OWPAcceptType	*aval	/* out - return accept value	*/
	);

/*
 * Used to determine how many local endpoints are still active.
 * (effectively calls the OWPTestSessionStatus function on all endpoints
 * and determines if they are complete yet.)
 *
 * If acceptval is non-null it is set to the MAX acceptval of any
 * complete session.
 *
 * returns:
 * 	number of active endpoints.
 */
extern int
OWPSessionsActive(
		OWPControl	cntrl,
		OWPAcceptType	*acceptval	/* rtn */
		);

/*
 * Send the StopSession message, and wait for the response.
 *
 * Client and Server.
 */
extern OWPErrSeverity
OWPStopSessions(
	OWPControl	control_handle,
	int		*retn_on_intr,
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
 * This is also useful in a policy context - getpeername can be called
 * on this descriptor.
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
 *
 *              If *rtn_on_intr and an inturrupt happens during write/read
 *              err_ret will be set to OWPErrWARNING.
 *
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
	OWPNum64	uptime,		/* uptime report		*/
	int		*retn_on_intr,	/* return on i/o interrupt	*/
	OWPErrSeverity	*err_ret	/* err - return			*/
		 );

typedef enum OWPRequestType{
	OWPReqInvalid=-1,
	OWPReqSockClose=0,
	OWPReqTest=1,
	OWPReqStartSessions=2,
	OWPReqStopSessions=3,
	OWPReqFetchSession=4
} OWPRequestType;

extern OWPRequestType
OWPReadRequestType(
		OWPControl	cntrl,
		int		*retn_on_intr
		);

extern OWPErrSeverity
OWPProcessTestRequest(
	OWPControl	cntrl,
	int		*retn_on_intr
		);

extern OWPErrSeverity
OWPProcessStartSessions(
	OWPControl	cntrl,
	int		*retn_on_intr
	);

extern OWPErrSeverity
OWPProcessStopSessions(
	OWPControl	cntrl
	);

extern OWPErrSeverity
OWPProcessFetchSession(
	OWPControl	cntrl,
	int		*retn_on_intr
	);

extern OWPContext
OWPGetContext(
	OWPControl	cntrl
	);

extern OWPSessionMode
OWPGetMode(
	OWPControl	cntrl
	);


/*
** Given the protocol family, OWAMP mode and packet padding,
** compute the size of resulting full IP test packet.
*/

/*
 * Payload size is used to determine how large the buffers need to be
 * to read a packet.
 */
extern OWPPacketSizeT
OWPTestPayloadSize(
		OWPSessionMode	mode,
		u_int32_t	padding
		);
/*
 * PacketSize is used to compute the full packet size - this is used to
 * determine bandwidth requirements for policy purposes.
 */
extern OWPPacketSizeT
OWPTestPacketSize(
		int		af,
		OWPSessionMode	mode,
		u_int32_t	padding
		);

/*
 * Returns # packets/second: 0.0 on error.
 */
extern double
OWPTestPacketRate(
		OWPContext	ctx,
		OWPTestSpec	*tspec
		);

/*
 * Returns bits/second: 0.0 on error.
 */
extern double
OWPTestPacketBandwidth(
		OWPContext	ctx,
		int		af,
		OWPSessionMode	mode,
		OWPTestSpec	*tspec
		);

extern u_int64_t
OWPFetchSession(
	OWPControl		cntrl,
	FILE			*fp,
	u_int32_t		begin,
	u_int32_t		end,
	OWPSID			sid,
	OWPErrSeverity		*err_ret
	);

/*
** Processing Session data to/from local disk.
*/

/*
 * This data structure is used to read/write a session header. When
 * reading a header, if the "header" element returns false, the file
 * did not contain any header information, and the remaining fields
 * are not valid.
 */
typedef struct OWPSessionHeaderRec{
	OWPBoolean		header;		/* RO: TestSession header? */
	u_int32_t		version;	/* RO: File version */
	u_int32_t		rec_size;	/* RO: data record size */
	OWPBoolean		finished;	/* RW: is session finished?
						 * 0:no,1:yes,2:unknown */
	u_int8_t		ipvn;		/* RO: ipvn of addrs */
	socklen_t		addr_len;	/* RO: saddr_len of saddrs */
	struct sockaddr_storage	addr_sender;
	struct sockaddr_storage	addr_receiver;
	OWPBoolean		conf_sender;
	OWPBoolean		conf_receiver;
	OWPSID			sid;
	OWPTestSpec		test_spec;
} OWPSessionHeaderRec, *OWPSessionHeader;

/*
** Applications use this type to manipulate individual timestamp data records.
*/
typedef struct OWPDataRec {
	u_int32_t    seq_no;
	OWPTimeStamp send;
	OWPTimeStamp recv;
} OWPDataRec;

/*
 * Write data header to the file.
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
 * Write data record to a file.
 * Returns:
 * 0	Success
 */
int
OWPWriteDataRecord(
		OWPContext		ctx,
		FILE			*fp,
		OWPDataRec		*rec
		);
/*
 * Returns:
 * number of records in the file. 0 on error. (errno will be set.)
 */
u_int32_t
OWPReadDataHeader(
		OWPContext		ctx,
		FILE			*fp,
		off_t			*hdr_len,
		OWPSessionHeader	hdr_ret
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
	OWPDataRec	*rec,
	void		*udata
       );

OWPErrSeverity
OWPParseRecords(
	OWPContext		ctx,
	FILE			*fp,
	u_int32_t		num_rec, 
	u_int32_t		file_version,	/* as reported by
						   OWPReadDataHeader */
	OWPDoDataRecord		proc_rec,
	void			*udata		/* passed into proc_rec */
	);

extern double
OWPDelay(
	OWPTimeStamp	*send_time,
	OWPTimeStamp	*recv_time
	);

extern OWPBoolean
OWPIsLostRecord(
	OWPDataRec	*rec
	);

/*
 * How much disk space will a given test require?
 * (This is only an estimate - duplicates/loss will change this.)
 */
extern u_int64_t
OWPTestDiskspace(
		OWPTestSpec	*tspec
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

extern OWPNum64
OWPGetRTTBound(
	OWPControl	cntrl
	);

extern double
OWPGetTimeStampError(
	OWPTimeStamp	*tstamp
	);

extern OWPTimeStamp *
OWPGetTimeOfDay(
	OWPTimeStamp	*tstamp
);

extern OWPTimeStamp *
OWPTimevalToTimestamp(
	OWPTimeStamp	*tstamp,
	struct timeval	*tval
);

extern struct timeval *
OWPTimestampToTimeval(
	struct timeval	*tval,
	OWPTimeStamp	*tstamp
	);

extern OWPTimeStamp *
OWPTimespecToTimestamp(
	OWPTimeStamp	*tstamp,
	struct timespec	*tval,
	u_int32_t	*errest,	/* usec's */
	u_int32_t	*last_errest	/* usec's */
	);

extern struct timespec *
OWPTimestampToTimespec(
	struct timespec	*tval,
	OWPTimeStamp	*tstamp
	);

#endif	/* OWAMP_H */
