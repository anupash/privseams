/** @file
 *  HIP Queue
 *  
 * @author: Pardeep Maheshwaree <pmaheshw@cc.hut.fi>
 * @note:   Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
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
int write_fifo_queue (void *write_data, int data_size_in_bytes)
{
	extern hip_queue *queue;
	void *temp_data;
	hip_queue *temp_traversal ;
	hip_queue *node ;
	int err = -1 ;
	
	_HIP_DEBUG ("Node data: %s \n",(char*)write_data);
	_HIP_DEBUG ("Node data: %d \n",data_size_in_bytes);
	temp_data = malloc(data_size_in_bytes);
	if (!temp_data)
	{
		err = -1 ;
		return err ;
	}
	memcpy (temp_data,write_data, data_size_in_bytes);
	_HIP_DEBUG ("Node data: %s \n",(char*)temp_data);
	if (!queue)
	{
		queue = malloc (sizeof(hip_queue));
		queue->next = NULL;
		queue->count = 0;
		queue->data = NULL ;
		queue->data_len =0;
	}
	if (queue->count == 0)
	{
		queue->data = temp_data ;
		queue->data_len = data_size_in_bytes;
	}
	else
	{
		temp_traversal = queue;
		node = malloc (sizeof(hip_queue));
		
		node->data_len = data_size_in_bytes;
		node->data = temp_data;
		node->next = NULL ;
		while (temp_traversal-> next !=NULL)
		{
			temp_traversal = temp_traversal-> next ;
		}
		temp_traversal-> next = node ;
	}
	queue->count++;
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
	extern hip_queue *queue ;
	if (queue && queue->count >0)
	{
		HIP_DEBUG ("Reading Node data. Current node count in queue: %d \n",queue->count);
		hip_queue *node = queue;
		queue = queue->next;
		memcpy (read_data,node->data, node->data_len);
		_HIP_DEBUG ("Node data read: %s \n",(char*)read_data);
		if (node->count >0)
		{
			free (node->data);
			free (node);
		}
		if(queue) /*When only 1 item queue will be NULL as it is set to queue->next now*/
		{
			queue->count = node->count;
			queue->count = queue->count -1;
		}
		return 0 ;
	}  
	HIP_DEBUG("No packet in the queue to be sent.\n");
	return -1;
}