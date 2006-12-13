#ifndef HIP_TIMER
#define HIP_TIMER
#if 1

#include <linux/time.h>

#define KMM_GLOBAL 1
#define KMM_PARTIAL 2
#define KMM_SPINLOCK 3

typedef struct timeval hip_timer_t;

#define HIP_START_TIMER(timer) do {\
      do_gettimeofday(&timer);\
 } while(0)

#define HIP_STOP_TIMER(timer, msg) do {\
      hip_timer_t hip_stop_timer; \
      hip_timer_t hip_timer_result; \
      do_gettimeofday(&hip_stop_timer);\
      hip_timeval_diff(&timer, &hip_stop_timer, &hip_timer_result);\
      HIP_INFO("%s: %ld usec\n", msg, \
               hip_timer_result.tv_usec + hip_timer_result.tv_sec * 1000000);\
 } while(0)

#endif /* 0 */
#endif
