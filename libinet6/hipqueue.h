/** @file
 * A header file for hipqueue.c
 * 
 * @author  Pardeep Maheshwaree <pmaheshw@cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 */
 
#ifndef _HIP_HIPQUEUE
#define _HIP_HIPQUEUE

#include <stdlib.h>
#include "debug.h"

typedef struct _hip_queue
{
	void* data;
	struct _hip_queue * next;
	int count;
	int data_len;
} hip_queue;

int write_fifo_queue (void *write_data, int data_size_in_bytes);
int read_fifo_queue (void *read_data);

#endif /* HIPQUEUE */
