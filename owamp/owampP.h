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

/*
 * Portablility sanity checkes.
 */
#if	HAVE_CONFIG_H
#include "config.h"

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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <owamp.h>
#include "rijndael-api-fst.h"

#define	_OWP_ERR_MAXSTRING	1024
#define	_OWP_DO_CIPHER		(OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

/* 
** Lengths (in 16-byte blocks) of various Control messages. 
*/
#define OWP_TEST_REQUEST_BLK_LEN     6
#define OWP_TEST_START_BLK_LEN       2
#define OWP_TEST_STOP_BLK_LEN        2
#define OWP_TEST_RETRIEVE_BLK_LEN    3

/*
 * Data structures
 */
typedef struct OWPContextRec OWPContextRec;
typedef struct OWPAddrRec OWPAddrRec;
typedef struct OWPControlRec OWPControlRec;

struct OWPContextRec{
	OWPInitializeConfigRec	cfg;
	OWPControlRec		*cntrl_list;
};

struct OWPAddrRec{
	OWPContext	ctx;

	OWPBoolean	node_set;
	char		node[MAXHOSTNAMELEN+1];

	OWPBoolean	port_set;
	char		port[MAXHOSTNAMELEN+1];

	OWPBoolean	ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	struct sockaddr	*saddr;
	socklen_t	saddrlen;

	OWPBoolean	fd_user;
	int		fd;
};

/*
 * Control state constants.
 */
/* initial */
#define	_OWPStateInitial	(0x00)
/* during negotiation */
#define	_OWPStateSetup		(0x01)
/* after negotiation ready for requests */
#define	_OWPStateRequest	(0x02)
/* test sessions are active  */
#define	_OWPStateTest		(0x04)

#define	_OWPStateIsInitial(c)	(!(c)->state)
#define	_OWPStateIsSetup(c)	(!(_OWPStateSetup ^ (c)->state))
#define	_OWPStateIsRequest(c)	(!(_OWPStateRequest ^ (c)->state))
#define	_OWPStateIsTest(c)	(!(_OWPStateTest ^ (c)->state))

typedef struct OWPTestSessionRec OWPTestSessionRec, *OWPTestSession;
struct OWPControlRec{
	/*
	 * Application configuration information.
	 */
	OWPContext		ctx;

	/*
	 * Control connection state information.
	 */
	OWPBoolean		server;	/* this record represents server */
	int			state;	/* current state of connection */
	OWPSessionMode		mode;

	/*
	 * Address specification and "network" information.
	 * (Control socket addr information)
	 */
	OWPAddr			remote_addr;
	OWPAddr			local_addr;
	int			sockfd;

	/*
	 * Encryption fields
	 */
	char			*kid; /* null if not set - else kid_buffer */
	char			kid_buffer[9];
	keyInstance             encrypt_key;
	keyInstance             decrypt_key;
	OWPByte			session_key[16];
	OWPByte			readIV[16];
	OWPByte			writeIV[16];

	struct OWPControlRec	*next;
	OWPTestSession		tests;
};

struct OWPTestSessionRec{
	OWPControl			cntrl;
	OWPSID				sid;
	OWPAddr				sender;
	OWPAddr				receiver;
	OWPBoolean			server_conf_sender;
	OWPBoolean			server_conf_receiver;
	void				*send_end_data;
	void				*recv_end_data;
	OWPTestSpec			test_spec;
	OWPTestSession			next;
};

/*
 * io.c prototypes
 */
extern ssize_t
_OWPReadn(
	int	fd,
	void	*buff,
	size_t	n
	 );

extern ssize_t
_OWPWriten(
	int		fd,
	const void	*buff,
	size_t		n
	  );

extern int
_OWPConnect(
	int		fd,
	struct sockaddr	*ai_addr,
	size_t		ai_addr_len,
	struct timeval	*tm_out
	   );

extern int
_OWPSendBlocks(
	OWPControl	cntrl,
	char		*buf,
	int		num_blocks
	      );

extern int
_OWPReceiveBlocks(
	OWPControl	cntrl,
	char		*buf,
	int		num_blocks
		);

extern int
_OWPEncryptBlocks(
	OWPControl	cntrl,
	char		*in_buf,
	int		num_blocks,
	char		*out_buf
		);

extern int
_OWPDecryptBlocks(
	OWPControl	cntrl,
	char		*in_buf,
	int		num_blocks,
	char		*out_buf
		);

extern int
_OWPMakeKey(
	OWPControl	cntrl,
	OWPByte		*binKey
	);

extern int
OWPEncryptToken(
	char	*binKey,
	char	*token_in,
	char	*token_out
	);

extern int
OWPDecryptToken(
	char	*binKey,
	char	*token_in,
	char	*token_out
	);

/*
 * random.c
 */
extern void
random_bytes(
	char	*ptr,
	int	count
	);

/*
 * cprotocol.c
 */
extern int
_OWPClientReadServerGreeting(
	OWPControl	cntrl,
	u_int32_t	*mode_avail_ret,
	OWPByte		*challenge_ret,
	OWPErrSeverity	*err_ret
		);

extern int
_OWPClientRequestModeReadResponse(
	OWPControl	cntrl,
	OWPByte		*token,
	OWPErrSeverity	*err_ret
);

/*
** sprotocol.c
*/

extern 
_OWPServerOK(OWPControl cntrl, u_int8_t code);

/*
 * context.c
 */
extern OWPBoolean
_OWPCallGetAESKey(
	OWPContext	ctx,		/* library context	*/
	const char	*kid,		/* identifies key	*/
	OWPByte		*key_ret,	/* key - return		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckAddrPolicy(
	OWPContext	ctx,		/* library context	*/
	struct sockaddr	*local_sa_addr,	/* local addr or NULL	*/
	struct sockaddr	*remote_sa_addr,/* remote addr		*/
	OWPErrSeverity	*err_ret	/* error - return	*/
);

extern OWPBoolean
_OWPCallCheckControlPolicy(
	OWPContext	ctx,		/* library context		*/
	OWPSessionMode	mode,		/* requested mode       	*/
	const char	*kid,		/* key identity			*/
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
	OWPTestSpec	*test_spec,	/* test requested		*/
	OWPErrSeverity	*err_ret	/* error - return		*/
);

extern OWPBoolean
_OWPCallEndpointInit(
        OWPControl      cntrl,
	void            **end_data_ret,
        OWPBoolean      send,
	OWPAddr         localaddr,
	OWPTestSpec     *test_spec,
	OWPSID          sid_ret,	/* only used if !send */
	OWPErrSeverity  *err_ret
);

extern OWPBoolean
_OWPCallEndpointInitHook(
        OWPControl      cntrl,
	void            *end_data,
	OWPAddr         remoteaddr,
	OWPSID		sid,
	OWPErrSeverity  *err_ret
);

extern OWPContext
OWPGetContext(OWPControl cntrl);

#endif	/* OWAMPP_H */
