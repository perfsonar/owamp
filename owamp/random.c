#include <owampP.h>

/*
** This function generates <count> many random bytes and
** places them in the location pointed to by <ptr>. It is
** a responsibility of the caller to have allocated
** sufficient space.
*/
void
random_bytes(char *ptr, int count)
{
	int i;
	long scale = (RAND_MAX / 1<<8);
	for (i = 0; i < count; i++)
		*(u_int8_t *)(ptr+i) = random()/scale; 
}
