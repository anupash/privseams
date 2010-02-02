/** @file
 * A header file for hipqueue.c
 * 
 * @author  Pardeep Maheshwaree <pmaheshw@cc.hut.fi>
 * @author  Samu Varjonen <samu.varjonen@hiit.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 */
 
#ifndef _HIP_HIPQUEUE
#define _HIP_HIPQUEUE

int hip_init_dht_queue(void);
int hip_write_to_dht_queue(void *, int);
int hip_read_from_dht_queue(void *);
void hip_dht_queue_uninit(void);

#endif /* HIPQUEUE */
