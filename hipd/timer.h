#ifndef HIP_TIMER
#define HIP_TIMER
#ifdef HIP_TIMING

#include <linux/time.h>

#define KMM_GLOBAL 1
#define KMM_PARTIAL 2
#define KMM_SPINLOCK 3

#define HIP_START_TIMER(mod) do {\
   if (mod == kmm) {\
      gtv_inuse = 1;\
      do_gettimeofday(&gtv_start);\
   }\
 } while(0)

#define HIP_STOP_TIMER(mod,msg) do {\
   if (mod == kmm) {\
      do_gettimeofday(&gtv_stop);\
      gtv_inuse = 0;\
      hip_timeval_diff(&gtv_start,&gtv_stop,&gtv_result);\
      HIP_INFO("%s: %ld usec\n", msg, \
               gtv_result.tv_usec + gtv_result.tv_sec * 1000000);\
   }\
 } while(0)

extern int kmm; // timer.c
extern struct timeval gtv_start, gtv_stop, gtv_result;
extern int gtv_inuse;
#else

#define HIP_START_TIMER(x)
#define HIP_STOP_TIMER(x,y)

#endif /* HIP_TIMING */
#endif
