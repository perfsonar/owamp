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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>

#ifndef	False
#define	False	(0)
#endif
#ifndef	True
#define	True	(!False)
#endif

#include <sys/param.h>

#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	64
#endif

#define	OWP_MODE_UNDEFINED		(0)
#define	OWP_MODE_OPEN			(01)
#define	OWP_MODE_AUTHENTICATED		(02)
#define	OWP_MODE_ENCRYPTED		(04)

#define CTRL_ACCEPT 0
#define CTRL_REJECT 1

/*
** Types of Control protocol messages.
*/
#define OWP_CTRL_REQUEST_SESSION         1
#define OWP_CTRL_START_SESSION           2
#define OWP_CTRL_STOP_SESSION            3
#define OWP_CTRL_RETRIEVE_SESSION        4

/* Default mode offered by the server */
#define OWP_DEFAULT_OFFERED_MODE 	(OWP_MODE_OPEN|OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/* Maximum message length in Control Protocol */
#define MAX_MSG 60 /* XXX - currently 56 but KID to be extended by 4 bytes */

/*
 * The 5555 should eventually be replaced by a IANA blessed service name.
 */
#define OWP_CONTROL_SERVICE_NAME	"5555"

/*
 * These structures are opaque to the API user.
 * They are used to maintain state internal to the library.
 */
typedef struct OWPContextRec	*OWPContext;
typedef struct OWPControlRec	*OWPControl;
typedef struct OWPAddrRec	*OWPAddr;

/* Codes for returning error severity and type. */
typedef enum {
	OWPErrFATAL=-4,
	OWPErrWARNING=-3,
	OWPErrINFO=-2,
	OWPErrDEBUG=-1,
	OWPErrOK=0
} OWPErrSeverity;

typedef enum {
	OWPErrPOLICY,
	OWPErrUNKNOWN
} OWPErrType;

#define	OWP_ERR_MAXSTRING	(1024)

typedef unsigned char	OWPByte;

typedef u_int32_t	OWPBoolean;
typedef OWPByte		OWPSID[16];
typedef OWPByte		OWPSequence[4];
typedef OWPByte		OWPKey[16];
typedef u_int32_t	OWPSessionMode;


typedef struct OWPTimeStampRec{
	unsigned long		sec:32;
	unsigned long		frac_sec:24;
	unsigned long		sync:1;
	unsigned long		prec:6;
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
} OWPPoissonTestSpec;

typedef struct{
	OWPTestType	test_type;
	OWPTimeStamp	start_time;
	u_int32_t	npackets;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
	/* make sure this is larger than any other TestSpec struct. */
	u_int32_t	padding[4];
} OWPTestSpec;

typedef struct OWPEndpointRec *OWPEndpoint;
struct OWPEndpointRec{
	OWPBoolean	receiver;	/* true if endpoint recv */

	struct sockaddr	local_saddr;
	struct sockaddr	remote_saddr;

	OWPSID		sid;
};

typedef enum {
	OWPEndpointInvalid,	/* invalid value	*/
	OWPEndpointReciever,
	OWPEndpointSender
} OWPEndpointType;

/*
 * The following types are used to initialize the library.
 */
/*
 * This type is used to define the function that is called whenever an error
 * is encountered within the library.
 * This function should return 0 on success and non-0 on failure. If it returns
 * failure - the default library error function will be called.
 */
typedef int (*OWPErrFunc)(
	void		*app_data,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*errmsg
);

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
	OWPByte		*key_ret,
	OWPErrSeverity	*err_ret
);

/*
 * If set, this function will be called from OWPControlOpen before the actual
 * connection is tried. This will allow the policy to determine if it
 * is willing to even speak "control" to that IP. (In the reference
 * implementation this just checks if the remote_addr is in the "forbidden"
 * class - and denies that. All other addresses are allowed at this point.)
 *
 * If local_sa_addr is NULL - then it is not being specified.
 * remote_sa_addr MUST be set.
 *
 * err_ret should be used to indicate a problem with the policy system - not
 * to indicate a negative response to this function. (However, err_ret can
 * be assumed to be "OK" if a positive response comes back from the function.)
 */
typedef OWPBoolean (*OWPCheckAddrPolicy)(
	void		*app_data,
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	OWPErrSeverity	*err_ret
);

/*
 * This function will be called from OWPControlOpen and OWPServerAccept
 * to determine if the control connection should be accepted.
 * It is called after connecting, and after determining the kid.
 */
typedef OWPBoolean (*OWPCheckControlPolicyFunc)(
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
	struct sockaddr	*local_sa_addr,
	struct sockaddr	*remote_sa_addr,
	OWPTestSpec	*test_spec,
	OWPErrSeverity	*err_ret
);

/*
 * Allocate port and set it in the *endpoint->sa_addr structure.
 * (different for IPV4 and IPV6? May need to call getsockname?)
 * (How do we detect if user passed FD in - don't need to bind!)
 * If "recv" - also allocate and set endpoint->sid
 */
typedef void (*OWPEndpointInitFunc)(
	void		*app_data,
	OWPEndpoint	endpoint,
	OWPErrSeverity	*err_ret
);

/*
 * Given remote_addr/port (can "connect" to remote addr now)
 * return OK
 */
typedef void (*OWPEndpointInitHookFunc)(
	void		*app_data,
	OWPEndpoint	local_endpoint,
	OWPEndpoint	remote_endpoint,
	OWPErrSeverity	*err_ret
);

/*
 * Given start session
 */
typedef void (*OWPEndpointStart)(
	void		*app_data,
	OWPEndpoint	endpoint,
	OWPErrSeverity	*err_ret
);

/*
 * Given stop session
 */
typedef void (*OWPEndpointStop)(
	void		*app_data,
	OWPEndpoint	endpoint,
	OWPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to retrieve the
 * current timestamp.
 */
typedef OWPTimeStamp (*OWPGetTimeStampFunc)(
	void		*app_data,
	OWPErrSeverity	*err_ret
);


/* 
 * This structure encodes parameters needed to initialize the library.
 */ 
typedef struct {
	struct timeval			tm_out;
	void				*app_data;
	OWPErrFunc			err_func;
	OWPGetAESKeyFunc		get_aes_key_func;
	OWPCheckAddrPolicy		check_addr_func;
	OWPCheckControlPolicyFunc	check_control_func;
	OWPCheckTestPolicyFunc		check_test_func;
	OWPEndpointInitFunc		endpoint_init_func;
	OWPEndpointInitHookFunc		endpoint_init_hook_func;
	OWPEndpointStart		endpoint_start_func;
	OWPEndpointStop			endpoint_stop_func;
	OWPGetTimeStampFunc		get_timestamp_func;
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
 * Error reporting routines - in the end these will just call the
 * function that is registered for the context as the OWPErrFunc
 */
extern void
OWPError(
	OWPContext	ctx,
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*fmt,
	...
);

#define OWPLine	__FILE__,__LINE__

extern void
OWPErrorLine(
	OWPContext	ctx,
	const char	*file,	/* fill with __FILE__ macro */
	int		line,	/* fill with __LINE__ macro */
	OWPErrSeverity	severity,
	OWPErrType	etype,
	const char	*fmt,
	...
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
	OWPAddr		local_addr,	/* src addr or NULL	*/
	OWPAddr		server_addr,	/* server addr or NULL	*/
	u_int32_t	mode_mask,	/* OR of OWPSessionMode */
	const char	*kid,		/* null if unwanted	*/
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
 * Once an EWPAddr record has been passed into this function, it
 * is automatically free'd. It should not be referenced again in any way.
 *
 * Client
 */
extern OWPBoolean
OWPRequestTestSession(
	OWPControl	control_handle,
	OWPAddr		sender,
	OWPBoolean	server_conf_sender,
	OWPAddr		receiver,
	OWPBoolean	server_conf_receiver,
	OWPTestSpec	*test_spec,
	OWPSID		sid_ret,
	OWPErrSeverity	*err_ret
);

/*
 * Start all test sessions - if successful, returns OWPErrOK.
 *
 * Client and Server
 */
extern OWPErrSeverity
OWPStartTestSessions(
	OWPControl	control_handle
);

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 * 	<0	ErrorCondition (can cast to OWPErrSeverity)
 * 	0	StopSessions received (OWPErrOK)
 * 	1	wake_time reached
 * 	2	CollectSession received from other side, and this side has
 * 		a receiver endpoint.
 *	3	system event (signal)
 *
 * Client and Server
 */
extern int
OWPWaitTestSessionStop(
	OWPControl	control_handle,
	OWPTimeStamp	wake_time,		/* abs time */
	OWPErrSeverity	*err_ret
);

/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the OWPWaitTestSessionStop
 * function so that the application can recieve user input, and only call
 * the OWPWaitTestSessionStop function when there is something to read
 * from the connection. (A timestamp in the past would be used in this case
 * so that OWPWaitTestSessionStop does not block.)
 *
 * If the control_handle is no longer connected - the function will return
 * a negative value.
 *
 * Client and Server.
 */
extern int
OWPGetControlFD(
	OWPControl	control_handle
);

/*
 * Send the StopSession message, and wait for the response.
 *
 * Client and Server.
 */
extern void
OWPSendStopSessions(
	OWPControl	control_handle,
	OWPErrSeverity	*err_ret
);

/*
** This function talks Control Protocol on the server side,
** up until on of the followinf events happends:
** 1) the Control connection is accepted and valid OWPControl handle returned;
** 2) the Control connection is rejected, and NULL is returned;
** 3) an error occurs, NULL is returned, plus extra diagnostics via err_ret.
*
* Server.
*/
extern OWPControl
OWPControlAccept(
		 OWPContext     ctx,       /* control context               */
		 u_int32_t      mode_offered,/* advertised server mode      */
		 int            connfd,    /* connected socket              */
		 void           *app_data, /* policy                        */
		 OWPErrSeverity *err_ret   /* err - return                  */
		 );
int
OWPServerReadRequest(OWPControl cntrl, char *buf);

/*
** Fetch context field of OWPControl structure.
*/
extern OWPContext
OWPGetContext(OWPControl cntrl);

/* 
** This function does the first policy check on the server. 
*/
extern OWPBoolean
OWPServerCheckAddrPolicy(OWPContext ctx, 
			 struct sockaddr *addr, 
			 OWPErrSeverity *err_ret
			 );

#endif	/* OWAMP_H */
