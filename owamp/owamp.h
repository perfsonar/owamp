/*
**      $Id$
*/
/************************************************************************
*									*
*			     Copyright (C)  2002			*
*	     University Corporation for Advanced Internet Development	*
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
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>

/*
 * Data structure
 */

/*
 * This structure is opaque to the API user...
 * It encodes parameters used by a party in Control session.
 */
typedef struct OWAMPControlConnectionRec *OWAMPControl;

/* Codes for returning error severity and type. */
typedef enum {
	OWAMPErrFATAL=-4,
	OWAMPErrWARNING=-3,
	OWAMPErrINFO=-2,
	OWAMPErrDEBUG=-1,
	OWAMPErrOK=0
} OWAMPErrSeverity;
typedef enum {
	OWAMPErrUNDEFINED
} OWAMPErrType;

typedef int		OWAMPBoolean;
typedef u_int8_t	OWAMP_SID[16];
typedef u_int32_t	OWAMP_Sequence;
typedef u_int32_t	OWAMP_KID;

typedef struct OWAMPTimeStampRec{
	u_int32_t		sec;
	u_int32_t		frac_sec;
	OWAMPBoolean		sync;
	u_int8_t		prec;
} OWAMPTimeStamp;

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
 * This type is used to define the function that is called to open a
 * test 'session log', meaning,  whatever the receiver may choose
 * to do with the test stream: write to disk, memory, file descriptor etc. 
 * It should return the SID that is to be used for the test stream.
 * (It will be called by the recv side.)
 */
typedef OWAMP_SID (*OWAMPLogOpenFunc)(
	void			*session_closure,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to write an
 * entry to the session log.
 */
typedef void (*OWAMPLogWriteFunc)(
	void			*session_closure,
	OWAMPSequence		n,
	OWAMPTimeStamp		sent,
	OWAMPTimeStamp		recv,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to close a
 * session log.
 */
typedef void (*OWAMPLogCloseFunc)(
	void			*session_closure,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to retrieve the
 * current timestamp.
 */
typedef OWAMPTimeStamp (*OWAMPGetTimeStampFunc)(
	void			*closure,
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
	OWAMPErrFunc		*errfunc;
	void			*err_closure;
	OWAMPLogOpenFunc	*session_open;	/* opens logfile-retn SID */
	OWAMPLogWriteFunc	*session_write;	/* called by recv	*/
	OWAMPLogCloseFunc	*session_close;	/* called by recv	*/
	void			*session_closure;
	OWAMPGetTimeStampFunc	*timestamp;	/* retn time/prec values */
	void			*timestamp_closure;
	OWAMPGetKeyFunc		*get_aes_key;
	void			*get_key_closure;
} *OWAMPInitializeConfig;

extern void
OWAMPInitialize(
	OWAMPInitializeConfig	config
);

#define	OWAMP_MODE_NONE			(0)
#define	OWAMP_MODE_UNAUTHENTICATED	(01)
#define	OWAMP_MODE_AUTHENTICATED	(02)
#define	OWAMP_MODE_ENCRYPTED		(04)
typedef u_int32_t	OWAMPSessionModes;

#define OWAMP_CONTROL_SESSIONMODE	(01)
#define OWAMP_CONTROL_SERVERNAME	(02)
#define OWAMP_CONTROL_SERVERADDR	(04)
#define OWAMP_CONTROL_SERVERSOCK	(010)
#define OWAMP_CONTROL_KEY		(011)
typedef u_int32_t	OWAMPControlConfigMask;

/*
 * Configure how the API makes the OWAMPOpenControl call.
 */
typedef struct {
			/*
			 * OWAMP_CONTROL_SESSIONMODE
			 *
			 * mode is hierarchical - highest
			 * level mode that is supported by
			 * server that matches this mask
			 * will be selected.
			 * enc->auth->unauth
			 *	default:OWAMP_MODE_UNAUTHENTICATED
			 */
	OWAMPSessionModes	mode;		/* mode mask requested */

			/*
			 * OWAMP_CONTROL_SERVERNAME
			 *
			 * serv_name is name of host to connect to
			 * as a dns resolvable hostname or as an
			 * ipv4 or ipv6 address in inet_ntop format.
			 *	default:localhost
			 */
	char			serv_name[MAXHOSTNAMELEN];
			/*
			 * OWAMP_CONTROL_SERVERADDR
			 *
			 * serv_af must be AF_INET or AF_INET6 and determines
			 * which variable contains the address:
			 * serv_in_addr or serv_in6_addr
			 */
	int			serv_af;
	struct	in_addr		serv_in_addr;
	struct	in6_addr	serv_in6_addr;
			/*
			 * OWAMP_CONTROL_SERVERSOCK
			 *
			 * If server_sock is set - then it should
			 * specify an already connected socket to the
			 * server. Only one of server_sock or serv_addr
			 * should be used.
			 * 	default:unused
			 */
	int			server_sock;
			/*
			 * OWAMP_CONTROL_KEY
			 *
			 * kid/key only used if mode includes
			 * auth or enc and OWAMPControlConfigMask
			 * sets OWAMP_CONTROL_KEY - then both must
			 * be set.
			 * 	default:unused
			 */
	OWAMPKID		kid;		/* kid of key for auth/enc*/
	OWAMPKey		key;		/* key for auth/enc */
} OWAMPControlConfig;

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
	OWAMPControlConfig	config,
	OWAMPControlConfigMask	mask,
	OWAMPErrSeverity	*err_ret
);

typedef u_int32_t	OWAMPSID[4];

typedef struct OWAMPEndpointRec *OWAMPEndpoint;

/*
 * This function is used to configure the address specification
 * for either one of the sender or receiver endpoints prior to
 * requesting the server to configure that endpoint.
 *
 * name refers to a hostname or address in textual format.
 * addr refers to either a (*struct in_addr) or a
 * (*struct in6_addr) depending upon value of af.
 *
 * af is also used to determine if IPv4 or IPv6 addresses are
 * valid when looking up "name" from the resolver. It should
 * be set to either AF_INET, AF_INET6, or AF_UNSPEC. (UNSPEC
 * means the api should use 6 if it can, and fall back to 4 if
 * not.)
 */
extern OWAMPEndpoint
OWAMPConfigEndpoint(
	char			*name,	/* endpoint hostname */
	char			*addr,	/* endpoint addr either in or in6 */
	int			af,	/* AF_UNSPEC if any *name* ok */
	OWAMPErrSeverity	*err_ret
);

extern OWAMPEndpoint
OWAMPCreateRecvEndpoint(
		local_addr
		openlog
		writelog
		closelog
		port
		gettimestamp
);

extern OWAMPEndpoint
OWAMPCreateSendEndpoint(
		local_addr
		port
		gettimestamp
);

typedef struct{
	u_int32_t	InvLambda;
	u_int32_t	npackets;
	u_int32_t	padding;
	OWAMPTimeStamp	start_time;
	u_int32_t	typeP;
} OWAMPTestSpec;

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

