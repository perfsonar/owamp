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
#include <sys/socket.h>

/*
 * Data structures
 */

/*
 * This structure is opaque to the API user...
 */
typedef struct OWAMPConnectionRec *OWAMPclient, *OWAMPserver;

typedef int		OWAMPErrSeverity;
typedef int		OWAMPErrFacility;
typedef int		OWAMPBoolean;
typedef u_int8_t	OWAMP_SID[16];
typedef u_int32_t	OWAMP_Sequence;
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
	OWAMPErrSeverity	severity,
	OWAMPErrFacility	etype,
	char			*errmsg,
	void			*closure
);

/*
 * This type is used to define the function that is called to open a session
 * log. It should return the SID that is to be used for the test stream.
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


typedef struct {
	OWAMPErrFunc		*errfunc;
	void			*err_closure;
	OWAMPSessionLogOpen	*session_open;	/* opens logfile - return SID */
	OWAMPSessionLogWrite	*session_write;	/* called by recv	*/
	OWAMPSessionLogClose	*session_close;	/* called by recv	*/
	void			*session_closure;
	OWAMPGetTimeStampFunc	*timestamp;	/* return time/prec values */
	void			*timestamp_closure;
	OWAMPGetKey		*get_aes_key;
	void			*get_key_closure;
} *OWAMPInitializeConfig;

extern void
OWAMPInitialize(
	OWAMPInitializeConfig	config
);

/*
 * Configure how the API makes the OWAMPOpen call.
 */
typedef struct {
	struct sockaddr	*serv_addr;
	socklen_t	serv_addr_len;
} OWAMPOpenConfig;
/*
 * OWAMPOpen allocates an OWAMPclient structure, opens a connection to the
 * OWAMP server specified by the OWAMPConfigOpen record, and goes through
 * the initialization phase of the connection. (This includes AES/CBC
 * negotiation.
 *
 * This is typically only used by an OWAMP client application (or a server
 * when acting as a client of another OWAMP server).
 */
extern OWAMPclient
OWAMPOpen(
	OWAMPOpenConfig		config,
	OWAMPOpenConfigMask	mask,
	OWAMPError		&err_ret
);


