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
#include <owampP.h>

/*
** Robust low-level IO functions - out of Stevens. Read or write
** the given number of bytes. Returns -1 on error. No short
** count is possible.
*/

/*
 * TODO: Add timeout values for read's and write's. We don't want to wait
 * as long as kernel defaults - timeout specified in the context is.
 */

ssize_t				       /* Read "n" bytes from a descriptor. */
_OWPReadn(int fd, void *vptr, size_t n)
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
/* end _OWPReadn */

ssize_t					/* Write "n" bytes to a descriptor. */
_OWPWriten(int fd, const void *vptr, size_t n)
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
/* end _OWPWriten */

/*
** This function sends a given number of (16 byte) blocks to the socket,
** doing encryption if needed.
*/

#define BLOCK_LEN    16 /* number of bytes in a block */

/*
** The next two functions send or receive a given number of
** (16-byte) blocks via the Control connection socket,
** taking care of encryption/decryption as necessary.
*/

#define RIJNDAEL_BLOCK_SIZE 16

int
_OWPSendBlocks(OWPControl cntrl, char* buf, int num_blocks)
{
	size_t n;

	if (! (cntrl->mode & _OWP_DO_CIPHER)){
		n = _OWPWriten(cntrl->sockfd, buf, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				"_OWPWriten failed");
			return -1;
		} 
		return 0;
	} else {
		char msg[MAX_MSG];
		_OWPEncryptBlocks(cntrl, buf, num_blocks, msg);
		n = _OWPWriten(cntrl->sockfd, msg, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "_OWPWriten failed");
			return -1;
		} 
		return 0;
	}
}

int
_OWPReceiveBlocks(OWPControl cntrl, char* buf, int num_blocks)
{
	size_t n;

	if (! (cntrl->mode & _OWP_DO_CIPHER)){
		n = _OWPReadn(cntrl->sockfd, buf, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "_OWPReadn failed");
			return -1;
		} 
		return 0;
	} else {
		char msg[MAX_MSG];
		n = _OWPReadn(cntrl->sockfd, msg, num_blocks*RIJNDAEL_BLOCK_SIZE);
		_OWPDecryptBlocks(cntrl, msg, num_blocks, buf);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "_OWPReadn failed");
			return -1;
		} 
		return 0;
	}	
}

/*
** The following two functions encrypt/decrypt a given number
** of (16-byte) blocks. IV is currently updated within
** the rijndael api (blockEncrypt/blockDecrypt).
*/

int
_OWPEncryptBlocks(OWPControl cntrl, char *buf, int num_blocks, char *out)
{
	int r;
	r = blockEncrypt(cntrl->writeIV, 
			 &cntrl->encrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;
}


int
_OWPDecryptBlocks(OWPControl cntrl, char *buf, int num_blocks, char *out)
{
	int r;
	r = blockDecrypt(cntrl->readIV, 
			 &cntrl->decrypt_key, buf, num_blocks*16*8, out);
	if (r != num_blocks*16*8)
		return -1;

}

/*
** This function sets up the key field of a OWPControl structure,
** using the binary key located in <binKey>.
*/

_OWPMakeKey(OWPControl cntrl, OWPByte *binKey)
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
OWPEncryptToken(char *binKey, char *token_in, char *token_out)
{
	int r;
	char IV[16];
	keyInstance key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupEnc(key.rk, binKey, 128);
	r = blockEncrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}

int
OWPDecryptToken(char *binKey, char *token_in, char *token_out)
{
	int r;
	char IV[16];
	keyInstance key;

	memset(IV, 0, 16);
	
	key.Nr = rijndaelKeySetupDec(key.rk, binKey, 128);
	r = blockDecrypt(IV, &key, token_in, TOKEN_BITS_LEN, token_out); 
			 
	if (r != TOKEN_BITS_LEN)
		return -1;

	return 0;
}
