/*
 *      $Id$
 */
/************************************************************************
*									*
*			     Copyright (C)  2003			*
*				Internet2				*
*			     All Rights Reserved			*
*									*
************************************************************************/
/*
 *	File:		owtvec.c
 *
 *	Author:		Jeff W. Boote
 *			Internet2
 *
 *	Date:		Mon Oct 20 13:55:38 MDT 2003
 *
 *	Description:	
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <I2util/util.h>
#include <owamp/owamp.h>

int
main(
	int	argc	__attribute__((unused)),
	char	**argv
) {
	char			*progname;
	I2LogImmediateAttr	ia;
	I2ErrHandle		eh;
	OWPContext		ctx;
	u_int8_t		seed[16];
	char			*seedvals[4] = {
			"2872979303ab47eeac028dab3829dab2",
			"0102030405060708090a0b0c0d0e0f00",
			"deadbeefdeadbeefdeadbeefdeadbeef",
			"feed0feed1feed2feed3feed4feed5ab"};
	int			nice[] = {1,10,100,1000,100000,1000000};
	unsigned int		i,j,n;
	OWPExpContext		exp;
	OWPNum64		eval;
	OWPNum64		sum;


	ia.line_info = (I2NAME | I2MSG);
#ifndef	NDEBUG
	ia.line_info |= (I2LINE | I2FILE);
#endif
	ia.fp = stderr;

	progname = (progname = strrchr(argv[0], '/')) ? ++progname : *argv;

	/*
	* Start an error logging session for reporing errors to the
	* standard error
	*/
	eh = I2ErrOpen(progname, I2ErrLogImmediate, &ia, NULL, NULL);
	if(! eh) {
		fprintf(stderr, "%s : Couldn't init error module\n", progname);
		exit(1);
	}

	/*
	 * Initialize library with configuration functions.
	 */
	if( !(ctx = OWPContextCreate(eh))){
		I2ErrLog(eh, "Unable to initialize OWP library.");
		exit(1);
	}

	for(i=0;i<I2Number(seedvals);i++){
		assert(OWPHexDecode(seedvals[i],seed,16));
		assert((exp = OWPExpContextCreate(ctx,seed)));
		fprintf(stdout,"SEED = 0x%s\n",seedvals[i]);
		n = 0;
		sum = OWPULongToNum64(0);
		for(j=1;j<=1000000;j++){
			eval = OWPExpContextNext(exp);
			sum = OWPNum64Add(sum,eval);
			if((n < I2Number(nice)) && (j == nice[n])){
				char	val[16];
				n++;
				OWPHexEncode(val,(u_int8_t*)&eval,8);

				fprintf(stdout,
					"EXP[%d] = 0x%s (%f)\tsum = %f\n",
					j,val,
					OWPNum64ToDouble(eval),
					OWPNum64ToDouble(sum));
			}
		}
		OWPExpContextFree(exp);
		exp = NULL;
		fprintf(stdout,"\n");
	}

	exit(0);
}
