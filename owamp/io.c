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
**	File:		io.c
**
**	Author:		Anatoly Karp
**
**	Date:		Wed Apr  24 10:42:12  2002
**
**	Description:	This file contains the private functions to
**			to facilitate IO that the library needs to do.
*/
#include <fcntl.h>
#include <owampP.h>

/*
** Robust low-level IO functions - out of Stevens. Read or write
** the given number of bytes. Returns -1 on error. No short
** count is possible.
*/

/*
 * TODO: Add timeout values for read's and write's. We don't want to wait
 * as long as kernel defaults - timeout is specified in the context.
 */

ssize_t				       /* Read "n" bytes from a descriptor. */
OWPReadn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;	   /* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}
/* end OWPReadn */

ssize_t					/* Write "n" bytes to a descriptor. */
OWPWriten(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (errno == EINTR)
				nwritten = 0;	  /* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}
/* end OWPWriten */


#define	tvalclear(a)	(a)->tv_sec = (a)->tv_usec = 0
#define tvaladd(a,b)					\
	do{						\
		(a)->tv_sec += (b)->tv_sec;		\
		(a)->tv_usec += (b)->tv_usec;		\
		if((a)->tv_usec >= 1000000){		\
			(a)->tv_sec++;			\
			(a)->tv_usec -= 1000000;	\
		}					\
	} while (0)
#define tvalsub(a,b)					\
	do{						\
		(a)->tv_sec -= (b)->tv_sec;		\
		(a)->tv_usec -= (b)->tv_usec;		\
		if((a)->tv_usec < 0){			\
			(a)->tv_sec--;			\
			(a)->tv_usec += 1000000;	\
		}					\
	} while (0)

int
_OWPConnect(
	int		fd,
	struct sockaddr	*ai_addr,
	size_t		ai_addr_len,
	struct timeval	*tm_out
)
{
	int		flags;
	int		rc;
	fd_set		rset,wset;
	size_t		len;
	struct timeval	end_time;
	struct timeval	curr_time;
	struct timeval	tout;

	flags = fcntl(fd, F_GETFL,0);
	fcntl(fd,F_SETFL,flags|O_NONBLOCK);

	rc = connect(fd,ai_addr,ai_addr_len);

	if(rc==0)
		goto DONE;

	if(errno != EINPROGRESS){
		return -1;
	}
	
	if(gettimeofday(&curr_time,NULL) != 0)
		return -1;

	tvalclear(&end_time);
	tvaladd(&end_time,&curr_time);
	tvaladd(&end_time,tm_out);

AGAIN:
	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	wset = rset;

	/*
	 * Set tout to (end_time-curr_time) - curr_time will get updated
	 * if there is an intr, so this is the "time left" from the original
	 * timeout.
	 */
	tvalclear(&tout);
	tvaladd(&tout,&end_time);
	tvalsub(&tout,&curr_time);
	rc = select(fd+1,&rset,&wset,NULL,&tout);
	if(rc == 0){
		errno = ETIMEDOUT;
		return -1;
	}
	if(rc < 0){
		if(errno == EINTR){
			if(gettimeofday(&curr_time,NULL) != 0)
				return -1;
			goto AGAIN;
		}
		return -1;
	}

	if(FD_ISSET(fd,&rset) || FD_ISSET(fd,&wset)){
		len = sizeof(rc);
		if(getsockopt(fd,SOL_SOCKET,SO_ERROR,(void*)&rc,&len) < 0){
			return -1;
		}
		if(rc != 0){
			errno = rc;
			return -1;
		}
	}else
		return -1;

DONE:
	fcntl(fd,F_SETFL,flags);
	return 0;
}

/*
** The next two functions send or receive a given number of
** _OWP_RIJNDAEL_BLOCK_SIZE blocks via the Control connection socket,
** taking care of encryption/decryption as necessary.
*/


int
_OWPSendBlocks(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks
	)
{
	ssize_t n;

	if (! (cntrl->mode & _OWP_DO_CIPHER)){
		n = OWPWriten(cntrl->sockfd, buf,
					num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,"OWPWriten failed:(%s)",
					strerror(errno));
			return -1;
		} 
		return 0;
	} else {
		u_int8_t	msg[_OWP_MAX_MSG];
		_OWPEncryptBlocks(cntrl, buf, num_blocks, msg);
		n = OWPWriten(cntrl->sockfd, msg,
					num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,"OWPWriten failed:(%s)",
					strerror(errno));
			return -1;
		} 
		return 0;
	}
}

int
_OWPReceiveBlocks(OWPControl cntrl, u_int8_t *buf, int num_blocks)
{
	ssize_t n;

	if (! (cntrl->mode & _OWP_DO_CIPHER)){
		n = OWPReadn(cntrl->sockfd, buf,
					num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,"OWPReadn failed:(%s)",
					strerror(errno));
			return -1;
		} 
		return 0;
	} else {
		u_int8_t	msg[_OWP_MAX_MSG];
		n = OWPReadn(cntrl->sockfd, msg,
					num_blocks*_OWP_RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,
					OWPErrUNKNOWN,"OWPReadn failed:(%s)",
					strerror(errno));
			return -1;
		} 
		_OWPDecryptBlocks(cntrl, msg, num_blocks, buf);
		return 0;
	}	
}

/*
** The following two functions encrypt/decrypt a given number
** of (16-byte) blocks. IV is currently updated within
** the rijndael api (blockEncrypt/blockDecrypt).
*/

int
_OWPEncryptBlocks(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	u_int8_t	*out
	)
{
	int r;
	r = blockEncrypt(cntrl->writeIV, 
			 &cntrl->encrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;
	return 0;
}


int
_OWPDecryptBlocks(
	OWPControl	cntrl,
	u_int8_t	*buf,
	int		num_blocks,
	u_int8_t	*out
	)
{
	int r;
	r = blockDecrypt(cntrl->readIV, 
			 &cntrl->decrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;
	return 0;
}

/*
** This function sets up the key field of a OWPControl structure,
** using the binary key located in <binKey>.
*/

void
_OWPMakeKey(
	OWPControl	cntrl,
	u_int8_t	*binKey
	)
{
	cntrl->encrypt_key.Nr
		= rijndaelKeySetupEnc(cntrl->encrypt_key.rk, binKey, 128);
	cntrl->decrypt_key.Nr 
		= rijndaelKeySetupDec(cntrl->decrypt_key.rk, binKey, 128);
}


/* 
** The next two functions perform a single encryption/decryption
** of Token in Control protocol, using a given (binary) key and the IV of 0.
*/

#define TOKEN_BITS_LEN (2*16*8)

int
OWPEncryptToken(
	unsigned char	*binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	u_int8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
	r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}

int
OWPDecryptToken(
	unsigned char	*binKey,
	unsigned char	*token_in,
	unsigned char	*token_out
	)
{
	int		r;
	u_int8_t	IV[16];
	keyInstance	key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
	r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}
