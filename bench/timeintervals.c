#include <stdio.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <assert.h>

/*
 * assuming 512k L2 cache, so keeping has bucket memory well below 128 4-byte
 * entries by using 64 buckets - power of two.
 */

main(){
        register u_int32_t	i,curr,prev;
	register u_int32_t	val;
	register u_int32_t	min,max,tmp;
	u_int32_t		under_min=0,over_max=0;
	u_int32_t		buckets[64];
        struct timeval		ts[2];

	memset(buckets,0,sizeof(buckets));
	memset(ts,0,sizeof(ts));

	/*
	 * First do a "short" test that should take ~10 seconds to
	 * get an estimate of max/min to determine bucket ranges.
	 * (estimating 5usec per gettimeofday() call to make this guess
	 * of 2 million iterations of the loop.)
	 */
        curr=0; prev=1;
	min=~0; max=0;
        gettimeofday(&ts[prev],NULL);
        for(i=0;i<2000000;i++){
		/*
		 * Assuming software clock is monotonic
		 */
                gettimeofday(&ts[curr],NULL);

		val = ts[curr].tv_sec - ts[prev].tv_sec;
		if(val > 1){
			fprintf(stderr,"val difference too huge!\n");
			exit(1);
		}

		val *= 1000000;
		val += ts[curr].tv_usec;
		val -= ts[prev].tv_usec;

		max = (val > max)? val : max;
		min = (val < min)? val : min;

		prev = curr;
                curr = (curr+1) % 2;
        }

	/*
	 * What range was seen in sub-sample?
	 * Extend min and max a bit beyond what is seen in this sample.
	 */
	assert(max>min);
	tmp = max - min;
	tmp *= 0.05;
	max += tmp;
	min *= 0.9;

min = 0;
max = 63;
	/*
	 * compute range for actual bucketing.
	 * Using simple shift for bucketing.
	 * Determine how many bits need to be shifted off.
	 * nbuckets == 64 == 2^6, so we keep 6 bits of precision, then
	 * count the number of bits that will need to be shifted off and lost.
	 */
	tmp = (max - min) >> 6;
	i=0;
	while(tmp){
		i++;
		tmp >>= 1;
	}

	/*
	 * save number of lost bits in 'tmp' var, reset max to the next
	 * power of two over min.
	 */
	tmp = i;
	max = min+(1<<(6+tmp));

        fprintf(stdout,"# min=%u usec, max=%u usec\n",min,max);
        fprintf(stdout,"# Loosing %u bits of precision from bucketing\n",tmp);

	/*
	 * Now do a real test - about 5 min's or 60000000 samples
	 * will hopefully be good.
	 */
        curr=0; prev=1;
        gettimeofday(&ts[prev],NULL);
#if NOT
        for(i=0;i<600000;i++,prev=curr,curr=(curr+1)%2){
#endif
        for(i=0;i<60000000;i++,prev=curr,curr=(curr+1)%2){
		/*
		 * Assuming software clock is monotonic
		 */
                gettimeofday(&ts[curr],NULL);

		val = ts[curr].tv_sec - ts[prev].tv_sec;
		if(val > 1){
			fprintf(stderr,
				"Real test!: val difference too huge!\n");
			exit(1);
		}

		val *= 1000000;
		val += ts[curr].tv_usec;
		val -= ts[prev].tv_usec;

		if(val > max){
			over_max++;
			continue;
		}
		if(val < min){
			under_min++;
			continue;
		}

		/*
		 * shift of bits of precision for bucketing.
		 */
		buckets[(val-min)>>tmp]++;
        }

	fprintf(stdout,"# min_bucket=%u\n# max_bucket=%u\n",min,max);
	fprintf(stdout,"# under_min=%u\n# over_max=%u\n\n",under_min,over_max);
	fprintf(stdout,"# Distribution follows: bucketn\tbucketc\tdelay(usec)\t\n");

	fprintf(stdout,"<%u\t%u\t<%u\n",0,under_min,min);
	for(i=0;i<64;i++){
		fprintf(stdout,"%u\t%u\t%u\n",i,buckets[i],min+(i<<tmp));
	}
	fprintf(stdout,">%u\t%u\t>%u\n",64,over_max,max);

        exit(0);
}
