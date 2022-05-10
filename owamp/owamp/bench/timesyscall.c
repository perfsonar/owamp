#include <stdio.h>
#include <sys/time.h>
#include <sys/timex.h>

main(){
        int     i=0;
        struct  timeval         val;
        struct  timeval         begin;
        struct  timeval         end;
        struct  ntptimeval      ntv;

#ifndef STA_NANO
        fprintf(stderr,"!NANO\n");
#else
        fprintf(stderr,"NANO\n");
#endif
        gettimeofday(&begin,NULL);
        while(i<10000000){
#ifdef  TESTNTP
                ntp_gettime(&ntv);
#else
                gettimeofday(&val,NULL);
#endif
                i++;
        }
        gettimeofday(&end,NULL);

        end.tv_sec -= begin.tv_sec;
        if(begin.tv_usec > end.tv_usec){
                end.tv_sec--;
                end.tv_usec += 1000000;
        }
        end.tv_usec -= begin.tv_usec;

        fprintf(stdout,"loop took:%u.%u\n",end.tv_sec,end.tv_usec);

        exit(0);
}
