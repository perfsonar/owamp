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
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>

#define	OWAMP_MODE_UNDEFINED		(0)
#define	OWAMP_MODE_UNAUTHENTICATED	(01)
#define	OWAMP_MODE_AUTHENTICATED	(02)
#define	OWAMP_MODE_ENCRYPTED		(04)

/*
 * This structure is opaque to the API user...
 * It encodes parameters used by a party in Control session.
 */
typedef struct OWAMPControlConnectionRec *OWAMPControl;
typedef struct OWAMPAddrRec *OWAMPAddr;

/* Codes for returning error severity and type. */
typedef enum {
	OWAMPErrFATAL=-4,
	OWAMPErrWARNING=-3,
	OWAMPErrINFO=-2,
	OWAMPErrDEBUG=-1,
	OWAMPErrOK=0
} OWAMPErrSeverity;

typedef enum {
	OWAMPErrPOLICY,
	OWAMPErrUNDEFINED
} OWAMPErrType;

typedef int		OWAMPBoolean;
typedef u_int32_t	OWAMPSID[4];
typedef u_int32_t	OWAMPSequence;
typedef char		OWAMPKID[8];
typedef u_int32_t	OWAMPSessionModes;


typedef struct OWAMPTimeStampRec{
	u_int32_t		sec;
	u_int32_t		frac_sec;
	OWAMPBoolean		sync;
	u_int8_t		prec;
} OWAMPTimeStamp;

typedef enum {
	OWAMPUnspecifiedTest,	/* invalid value	*/
	OWAMPPoissonTest
} OWAMPTestType;

typedef struct{
	OWAMPTestType	test_type;
	OWAMPTimeStamp	start_time;
	u_int32_t	npackets;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
	u_int32_t	InvLambda;
} OWAMPPoissonTestSpec;

typedef struct{
	OWAMPTestType	test_type;
	OWAMPTimeStamp	start_time;
	u_int32_t	npackets;
	u_int32_t	typeP;
	u_int32_t	packet_size_padding;
	/* make sure this is larger then any other TestSpec struct. */
	u_int32_t	padding[4];
} OWAMPTestSpec;

struct OWAMPEndpointRec{
	OWAMPBoolean		receiver;	/* true if endpoint recv */

	struct sockaddr		sa_addr;

	OWAMPSID		sid;
};

typedef struct OWAMPEndpointRec *OWAMPEndpoint;

/*
 * The following types are used to initialize the library.
 */
/*
 * This type is used to define the function that is called whenever an error
 * is encountered within the library.
 * This function should return 0 on success and non-0 on failure. If it returns
 * failure - the default library error function will be called.
 */
typedef int (*OWAMPErrFunc)(
	void			*closure,
	OWAMPErrSeverity	severity,
	OWAMPErrType		etype,
	char			*errmsg
);

/*
 * The value that is returned from this function will be passed
 * as app_data to the OWAMPCheckTestPolicyFunc,
 * EndpointInitFunc, EndpointInitHookFunc,
 * EndpointStartFunc and EndpointStopFunc.
 *
 * If the application defines the OWAMPCheckControlPolicyFunc, and
 * the return value represents dynamic memory - the application must
 * also define the OWAMPFreeControlPolicyDataFunc as a way to free
 * that memory.
 */
typedef void* (*OWAMPCheckControlPolicyFunc)(
	OWAMPSessionModes	mode_req,
	OWAMPKID		kid,
	struct sockaddr		*local_sa_addr,
	struct sockaddr		*remote_sa_addr,
	OWAMPErrSeverity	*err_ret
);

/*
 * This function will be called by OWAMPRequestTestSession if
 * one of the endpoints of the test is on the localhost before
 * it calls the EndpointInit*Func's. If err_ret returns
 * OWAMPErrFATAL, OWAMPRequestTestSession will not continue, and return
 * OWAMPErrFATAL as well.
 *
 * endpoint->sid will not be valid yet.
 * Only the IP address values will be set in the sockaddr structures -
 * i.e. port numbers will not be valid.
 */
typedef void (*OWAMPCheckTestPolicyFunc)(
	void			*app_data,
	OWAMPTestSpec		*test_spec,
	OWAMPEndpoint		local,
	OWAMPEndpoint		remote,
	OWAMPErrSeverity	*err_ret
);

/*
 * Allocate port and set it in the *endpoint->sa_addr structure.
 * (different for IPV4 and IPV6? May need to call getsockname?)
 * (How do we detect if user passed FD in - don't need to bind!)
 * If "recv" - also allocate and set endpoint->sid
 */
typedef void (*OWAMPEndpointInitFunc)(
	void			*app_data,
	OWAMPEndpoint		endpoint,
	OWAMPErrSeverity	*err_ret
);

/*
 * Given remote_addr/port (can "connect" to remote addr now)
 * return OK
 */
typedef void (*OWAMPEndpointInitHookFunc)(
	void			*app_data,
	OWAMPEndpoint		local_endpoint,
	OWAMPEndpoint		remote_endpoint,
	OWAMPErrSeverity	*err_ret
);

/*
 * Given start session
 */
typedef void (*OWAMPEndpointStart)(
	void			*app_data,
	OWAMPEndpoint		endpoint,
	OWAMPErrSeverity	*err_ret
);

/*
 * Given stop session
 */
typedef void (*OWAMPEndpointStop)(
	void			*app_data,
	OWAMPEndpoint		endpoint,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to retrieve the
 * current timestamp.
 */
typedef OWAMPTimeStamp (*OWAMPGetTimeStampFunc)(
	void			*app_data,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 */
typedef OWAMPKey	(*OWAMPGetKeyFunc)(
	void			*closure,
	OWAMPKID		kid,
	OWAMPErrSeverity	*err_ret
);


/* 
 * This structure encodes parameters needed to initialize the library.
 */ 
typedef struct {
	time_sec_perhaps		tm_out;
	OWAMPErrFunc			*errfunc;
	void				*err_closure;
	OWAMPGetKeyFunc			*get_aes_key;
	void				*get_aes_key_closure;
	OWAMPCheckControlPolicyFunc	*check_control_func;
	OWAMPCheckTestPolicyFunc	*check_test_func;
	OWAMPEndpointInitFunc		*check_control_func;
	OWAMPEndpointInitHookFunc	*check_control_func;
	OWAMPEndpointStart		*check_control_func;
	OWAMPEndpointStop		*check_control_func;
	OWAMPGetTimeStampFunc		*timestamp;
} *OWAMPInitializeConfig;


/*
 * API Functions
 *
 */

extern void
OWAMPInitialize(
	OWAMPInitializeConfig	config
);

/*
 * The OWAMPAddrBy* functions are used to allow the OWAMP API to more
 * adequately manage the memory associated with the many different ways
 * of specifying an address - and to provide a uniform way to specify an
 * address to the main API functions.
 * These functions return NULL on failure. (They call the error handler
 * to specify the reason.)
 */
extern OWAMPAddr
OWAMPAddrByNode(
	char	*node	/* dns or valid charactor representation of addr */
);

extern OWAMPAddr
OWAMPAddrByAddrInfo(
	struct addrinfo	*ai	/* valid addrinfo linked list	*/
);

extern OWAMPAddr
OWAMPAddrBySockFD(
	int	fd	/* fd must be an already connected socket */
);

/*
 * OWAMPOpenControl allocates an OWAMPclient structure, opens a connection to
 * the OWAMP server and goes through the initialization phase of the
 * connection. This includes AES/CBC negotiation. It returns after receiving
 * the ServerOK message.
 *
 * This is typically only used by an OWAMP client application (or a server
 * when acting as a client of another OWAMP server).
 *
 * err_ret values:
 * 	OWAMPErrOK	completely successful - highest level mode ok'd
 * 	OWAMPErrWARNING	session connected but future problems possible
 * 	OWAMPErrINFO	session connected with less than highest level mode
 * 	OWAMPErrFATAL	function will return NULL - connection is closed.
 * 		(Errors will have been reported through the OWAMPErrFunc
 * 		in all cases.)
 * function return values:
 * 	If successful - even marginally - a valid OWAMPclient handle
 * 	is returned. If unsuccessful, NULL is returned.
 */
extern OWAMPControl
OWAMPOpenControl(
	OWAMPAddr		server_addr,
	int			mode_mask,	/* OR of OWAMPSessionModes */
	OWAMPKID		*kid,		/* null if unwanted	*/
	OWAMPKey		*key,		/* null if unwanted	*/
	OWAMPErrSeverity	*err_ret
);

/*
 * This function is used to configure the address specification
 * for either one of the sender or receiver endpoints prior to
 * requesting the server to configure that endpoint.
 */
extern OWAMPEndpoint
OWAMPServerConfigEndpoint(
	OWAMPAddr		addr,
	OWAMPErrSeverity	*err_ret
);

/*
 * This function is used to configure a reciever on this host
 */
extern OWAMPEndpoint
OWAMPCreateRecvEndpoint(
	OWAMPAddr		addr,
	OWAMPErrSeverity	*err_ret
);

/*
 * This function is used to configure a sender on this host
 */
extern OWAMPEndpoint
OWAMPCreateSendEndpoint(
	OWAMPAddr		addr,
	OWAMPErrSeverity	*err_ret
);

/*
 * Request a test session - if err_ret is OWAMPErrOK - then the function
 * returns a valid SID for the session.
 */
extern OWAMPSID
OWAMPRequestTestSession(
	OWAMPControl		control_handle,
	OWAMPEndpoint		sender,
	OWAMPEndpoint		receiver,
	OWAMPTestSpec		test_spec
	OWAMPErrSeverity	*err_ret
);

/*
 * Start all test sessions - if successful, err_ret is OWAMPErrOK.
 */
extern void
OWAMPStartTestSessions(
	OWAMPControl		control_handle,
	OWAMPErrSeverity	*err_ret
);

/*
 * If a send/recv endpoint is part of the local application, use
 * this function to start it after the OWAMPStartTestSessions function
 * returns successfully.
 */
extern void
OWAMPStartEndpoint(
	OWAMPEndpoint		send_or_recv,
	OWAMPErrSeverity	*err_ret
);

/*
 * Wait for test sessions to complete. This function will return the
 * following integer values:
 * 	<0	ErrorCondition (can cast to OWAMPErrSeverity)
 * 	0	StopSessions received (OWAMPErrOK)
 * 	1	wake_time reached
 * 	2	CollectSession received from other side, and this side has
 * 		a receiver endpoint.
 *	3	system event (signal)
 */
extern int
OWAMPWaitTestSessionStop(
	OWAMPControl		control_handle,
	OWAMPTimeStamp		wake_time,		/* abs time */
	OWAMPErrSeverity	*err_ret
);

/*
 * Return the file descriptor being used for the control connection. An
 * application can use this to call select or otherwise poll to determine
 * if anything is ready to be read but they should not read or write to
 * the descriptor.
 * This can be used in conjunction with the OWAMPWaitTestSessionStop
 * function so that the application can recieve user input, and only call
 * the OWAMPWaitTestSessionStop function when there is something to read
 * from the connection. (A timestamp in the past would be used in this case
 * so that OWAMPWaitTestSessionStop does not block.)
 *
 * If the control_handle is no longer connected - the function will return
 * a negative value.
 */
extern int
OWAMPGetControlFD(
	OWAMPControl	control_handle
);

/*
 * Send the StopSession message, and wait for the response.
 */
extern void
OWAMPSendStopSessions(
	OWAMPControl		control_handle,
	OWAMPErrSeverity	*err_ret
);

#endif	/* OWAMP_H */
