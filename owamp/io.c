#include <owampP.h>

/*
** Robust low-level IO functions - out of Stevens. Read or write
** the given number of bytes. Returns -1 on error. No short
** count is possible.
*/

ssize_t				       /* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
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
/* end readn */

ssize_t					/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
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
/* end writen */

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

	if (! (cntrl->mode && OWP_MODE_ENCRYPTED)){
		n = writen(cntrl->sockfd, buf, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				"writen failed");
			return -1;
		} 
		return 0;
	} else {
		char msg[MAX_MSG];
		_OWPEncryptBlocks(cntrl, buf, num_blocks, msg);
		n = writen(cntrl->sockfd, msg, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "writen failed");
			return -1;
		} 
		return 0;
	}
}

int
_OWPReceiveBlocks(OWPControl cntrl, char* buf, int num_blocks)
{
	size_t n;

	if (! (cntrl->mode && OWP_MODE_ENCRYPTED)){
		n = readn(cntrl->sockfd, buf, num_blocks*RIJNDAEL_BLOCK_SIZE);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "readn failed");
			return -1;
		} 
		return 0;
	} else {
		char msg[MAX_MSG];
		n = readn(cntrl->sockfd, msg, num_blocks*RIJNDAEL_BLOCK_SIZE);
		_OWPDecryptBlocks(cntrl, msg, num_blocks, buf);
		if (n < 0){
			OWPErrorLine(cntrl->ctx,OWPLine,OWPErrFATAL,errno,
				     "readn failed");
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
