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

#include <owamp.h>
#include "rijndael-api-fst.h"

#define	_OWP_ERR_MAXSTRING	1024
#define	_OWP_DO_CIPHER		(OWP_MODE_AUTHENTICATED|OWP_MODE_ENCRYPTED)

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

	OWPBoolean	ai_free;	/* free ai list directly...*/
	struct addrinfo	*ai;

	OWPBoolean	saddr_set;
	struct sockaddr	saddr;

	OWPBoolean	fd_user;
	int		fd;
};

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
};

struct OWPTestSessionRec{
	struct sockaddr			send_addr;
	struct sockaddr			recv_addr;
	struct OWPTestSessionRec	*next;
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

#endif	/* OWAMPP_H */
