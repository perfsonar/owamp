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
** This function sends a given number of blocks to the socket,
** doing encryption if needed.
*/

#define BLOCK_LEN    16 /* number of bytes in a block */

int
send_blocks(int sock, char *buf, int num_blocks, OWPBoolean encrypt)
{
	if (!encrypt){
		if (writen(sock, buf, num_blocks*BLOCK_LEN) < 0)
			return -1;
	}
	return 0;
}
