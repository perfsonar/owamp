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
 * Data structures
 */

/*
 * This structure is opaque to the API user...
 * It encodes parameters used by a party in Control session.
 */
typedef struct OWAMPConnectionRec *OWAMPclient, *OWAMPserver;

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
typedef OWAMP_SID (*OWAMPSessionLogOpen)(
	void			*session_closure,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to write an
 * entry to the session log.
 */
typedef void (*OWAMPSessionLogWrite)(
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
typedef void (*OWAMPSessionLogClose)(
	void			*session_closure,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that is called to retrieve the
 * current timestamp.
 */
typedef OWAMPTimeStamp (*OWAMPGetTimeStamp)(
	void			*closure,
	OWAMPErrSeverity	*err_ret
);

/*
 * This type is used to define the function that retrieves the shared
 * secret from whatever key-store is in use.
 */
typedef OWAMPKey	(*OWAMPGetKey)(
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
	OWAMPSessionLogOpen	*session_open;	/* opens logfile-retn SID */
	OWAMPSessionLogWrite	*session_write;	/* called by recv	*/
	OWAMPSessionLogClose	*session_close;	/* called by recv	*/
	void			*session_closure;
	OWAMPGetTimeStamp	*timestamp;	/* retn time/prec values */
	void			*timestamp_closure;
	OWAMPGetKey		*get_aes_key;
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

#define OWAMP_OPEN_SETMODE		(01)
#define OWAMP_OPEN_SETSERVERNAME	(02)
#define OWAMP_OPEN_SETSERVERADDR	(04)
#define OWAMP_OPEN_SETSERVERSOCK	(010)
#define OWAMP_OPEN_SETKEY		(011)
typedef u_int32_t	OWAMPOpenConfigMask;

/*
 * Configure how the API makes the OWAMPOpen call.
 */
typedef struct {
			/*
			 * OWAMP_OPEN_SETMODE
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
			 * OWAMP_OPEN_SETSERVERNAME
			 *
			 * serv_name is name of host to connect to
			 * as a dns resolvable hostname or as an
			 * ipv4 or ipv6 address in inet_ntop format.
			 *	default:localhost
			 */
	char			serv_name[MAXHOSTNAMELEN];
			/*
			 * OWAMP_OPEN_SETSERVERADDR
			 *
			 * serv_af is AF_INET or AF_INET6 and determines
			 * how the address is set:
			 * Using serv_in_addr or serv_in6_addr.
			 */
	int			serv_af;
	struct	in_addr		serv_in_addr;
	struct	in6_addr	serv_in6_addr;
			/*
			 * OWAMP_OPEN_SETSERVERSOCK
			 *
			 * If server_sock is set - then it should
			 * specify an already connected socket to the
			 * server. Only one of server_sock or serv_addr
			 * should be used.
			 * 	default:unused
			 */
	int			server_sock;
			/*
			 * OWAMP_OPEN_SETKEY
			 *
			 * kid/key only used if mode includes
			 * auth or enc and OWAMPOpenConfigMask
			 * sets OWAMP_OPEN_SETKEY - then both must
			 * be set.
			 * 	default:unused
			 */
	OWAMPKID		kid;		/* kid of key for auth/enc*/
	OWAMPKey		key;		/* key for auth/enc */
} OWAMPOpenConfig;

/*
 * OWAMPOpen allocates an OWAMPclient structure, opens a connection to the
 * OWAMP server specified by the OWAMPConfigOpen record, and goes through
 * the initialization phase of the connection. This includes AES/CBC
 * negotiation. It returns after recieving the ServerOK message.
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
extern OWAMPclient
OWAMPOpen(
	OWAMPOpenConfig		config,
	OWAMPOpenConfigMask	mask,
	OWAMPErrSeverity	*err_ret
);

typedef u_int32_t	OWAMPSID[4];

#define OWAMP_REQUEST_		(01)
typedef u_int32_t	OWAMPRequestConfigMask;

typedef struct{
	u_int32_t	InvLambda;
	u_int32_t	npackets;
	u_int32_t	padding;
	u_int64_t	start_time;
	u_int32_t	typeP;
} OWAMPTestSpec;

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
extern OWAMPTestEndpoint
OWAMPConfigEndpoint(
	char			*name,	/* endpoint hostname */
	char			*addr,	/* endpoint addr either in or in6 */
	int			af,	/* AF_UNSPEC if any *name* ok */
	OWAMPErrSeverity	*err_ret
);

extern OWAMPTestEndpoint
OWAMPCreateReceiver(
		local_addr
		openlog
		writelog
		closelog
		port
		gettimestamp
);

extern OWAMPTestEndpoint
OWAMPCreateSender(
		local_addr
		port
		gettimestamp
);

extern OWAMPSID
OWAMPRequestSession(
	OWAMPclient		OWAMPptr,
	OWAMPTestEndpoint	sender,
	OWAMPTestEndpoint	receiver,
	OWAMPTestSpec		test_spec
	OWAMPErrSeverity	*err_ret
);
