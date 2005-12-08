#include "timer.h"

#ifdef HIP_TIMING
struct timeval gtv_start;
struct timeval gtv_stop;
struct timeval gtv_result;
int gtv_inuse;
int kmm; // krisu_measurement_mode

MODULE_PARM(kmm,"i");
MODULE_PARM_DESC(kmm, "Measuring mode: 1 = Global timing, 2 = {I,R}{1,2} timing, 3 = spinlock timing");
#endif
