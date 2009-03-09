/** @file
 *  HIP Queue
 *  
 * @author: Pardeep Maheshwaree <pmaheshw@cc.hut.fi>
 * @author: Samu Varjonen <samu.varjonen@hiit.fi>
 * @note:   Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>. This is actually a singly linked list. -samu
 */

/******************************************************************************/
/* INCLUDES */
#include "hipqueue.h"
/******************************************************************************/

/**
* write_fifo_queue - This function writes data to the hip_queue structure
* @param write_data data to be written on the queue node
* @param data_size_in_bytes size of the data sent
* @return status of the operation 0 on success, -1 on failure
*/
int write_fifo_queue (void *write_data, int data_size_in_bytes) {
	extern struct hip_queue *queue;
	extern int queue_count;
	void *temp_data;
	struct hip_queue *temp_traversal;
	struct hip_queue *node;
	int err = -1;
	
	temp_data = malloc(data_size_in_bytes);
	HIP_IFEL((!temp_data), -1, "Failed to malloc memory for data\n");
	memset(temp_data, 0, sizeof(data_size_in_bytes));
	memcpy (temp_data,write_data, data_size_in_bytes);
	if (!queue) {
		queue = malloc (sizeof(struct hip_queue));
		queue->next = NULL;
		queue->data = NULL;
		queue->data_len =0;
		queue_count = 0;
	}
	if (queue_count == 0) { 
		queue->data = temp_data;
		queue->data_len = data_size_in_bytes; 
		queue_count = queue_count + 1;
	} else if (queue_count > 0) {
		node = (struct hip_queue *)malloc(sizeof(struct hip_queue));
		memset(node, 0, sizeof(struct hip_queue));
		HIP_IFEL((!node), -1, "Failed to malloc memory for queue node\n");
		node->data_len = data_size_in_bytes;
		node->data = temp_data;
		node->next = NULL;

		/* Find the end of queue */
		temp_traversal = queue;
		while (temp_traversal->next != NULL)
			temp_traversal = temp_traversal->next;
		temp_traversal->next = node;
		queue_count = queue_count + 1;
	} else 
		HIP_DEBUG("ERROR in queue_count value!\n");
	/* Debug line do not leave uncommented */
	//debug_print_queue();
	out_err:
	/* Why zeroed -samu */
	err = 0 ;	
	return err ;  
}

/**
* read_fifo_queue - This function writes data to the hip_queue structure
* @param read_data stores the data read from queue node
* @return status of the operation 0 on success, -1 on failure
*/
int read_fifo_queue (void *read_data)
{
	extern struct hip_queue *queue;
	extern int queue_count;
    
	if (queue && queue_count > 0) {
		HIP_DEBUG ("Reading Node data. Current node count in queue: %d \n",queue_count);
		struct hip_queue *node = queue;
		queue = queue->next;
		memcpy (read_data, node->data, node->data_len);
		HIP_DEBUG ("Node data read: %s \n", (char*)read_data);
		if (queue_count > 0) {
			free (node->data);
			free (node);
		}
		queue_count = queue_count -1;
		/* Debug line do not leave uncommented */
		//debug_print_queue();
		return 0 ;
	}  
	HIP_DEBUG("No packet in the queue to be sent.\n");
	return -1;
}

/** 
 * debug_print_queue - This function prints all the queue members
 *
 @ return void
*/
void debug_print_queue() {
	extern struct hip_queue *queue;
	struct hip_queue *traversal;
	extern int queue_count;

	HIP_DEBUG("DEBUGGING QUEUE comment out if left uncommented\n");
	traversal = queue;
	HIP_DEBUG("Head count %d\n", queue_count);
	if (queue_count > 0) {
		while (traversal->next != NULL) { 
			HIP_DEBUG("Node data_len = %d\n", traversal->data_len);
			HIP_DEBUG("Node data= %s\n", traversal->data);
			traversal = traversal->next;
		}
		HIP_DEBUG("Node data_len = %d\n", traversal->data_len);
		HIP_DEBUG("Node data= %s\n", traversal->data);
	} else if (queue_count == 1){
		HIP_DEBUG("Node data_len = %d\n", traversal->data_len);
		HIP_DEBUG("Node data= %s\n", traversal->data);
	} else 
		HIP_DEBUG("Queue empty\n");
}
