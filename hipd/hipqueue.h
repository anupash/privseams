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
#include "debug.h"

struct hip_queue
{
	void* data;
	int data_len;
	struct hip_queue * next;
};

int write_fifo_queue (void *write_data, int data_size_in_bytes);
int read_fifo_queue (void *read_data);
void debug_print_queue();

#endif /* HIPQUEUE */
