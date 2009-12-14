/** @file
 * A header file for hipqueue.c
 * 
 * @author  Pardeep Maheshwaree <pmaheshw@cc.hut.fi>
 * @author  Samu Varjonen <samu.varjonen@hiit.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 */
 
#ifndef _HIP_HIPQUEUE
#define _HIP_HIPQUEUE

#include <stdlib.h>
#include "hashtable.h"
#include "debug.h"

struct hip_queue
{
	void * data;
	int data_len;
};

unsigned long hip_hash_opendht_queue(const struct hip_queue *);
int hip_compare_opendht_queue(const struct hip_queue *, const struct hip_queue *);
int hip_init_opendht_queue();
int hip_write_to_opendht_queue (void *, int);
int hip_read_from_opendht_queue (void *);
int hip_read_from_dht_queue (void *);
void hip_debug_print_opendht_queue();
int hip_init_dht_queue();
int hip_write_to_dht_queue (void *, int);

#endif /* HIPQUEUE */
