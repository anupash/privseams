/** @file
 *  HIP Queue
 *
 * @author: Samu Varjonen <samu.varjonen@hiit.fi>
 * @note:   Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>. This is actually a singly linked list. -samu
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include <stdlib.h>
#include "lib/core/hashtable.h"
#include "lib/core/debug.h"

#include "dhtqueue.h"
#include "lib/core/misc.h"

struct hip_queue {
    void *data;
    int   data_len;
};

HIP_HASHTABLE *hip_dht_queue = NULL;

/**
 * hip_dht_queue_hash
 *
 * Hash callback for LHASH used to store the item into the hashtable
 *
 * @param item hip_queue structure to be hashed
 *
 * @return the hash as unsigned long
 *
 * @note only for internal use in this file
 */
unsigned long hip_dht_queue_hash(const struct hip_queue *item)
{
    uint8_t hash[HIP_AH_SHA_LEN];
    hip_build_digest(HIP_DIGEST_SHA1,
                     (void *) item,
                     sizeof(struct hip_queue),
                     hash);
    return *((unsigned long *) (void *) hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_dht_queue, const struct hip_queue)

/**
 * hip_dht_queue_cmp - Compare callback for LHASH
 *
 * @param item1 first item to be compared
 * @param item2 second item to be compared
 *
 * @return 0 on equal otherwise non-zero
 */
static int hip_dht_queue_cmp(const struct hip_queue *item1,
                             const struct hip_queue *item2)
{
    return strcmp((char *) item1, (char *) item2);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_dht_queue, const struct hip_queue)

/**
 * hip_init_dht_queue - This function initializes the opedht_queue
 *
 * @return status of the operation 0 on success, -1 on failure
 */
int hip_init_dht_queue()
{
    if (hip_dht_queue == NULL) {
        hip_dht_queue = hip_ht_init(LHASH_HASH_FN(hip_dht_queue),
                                    LHASH_COMP_FN(hip_dht_queue));
    }
    if (hip_dht_queue == NULL) {
        return -1;
    }
    return 0;
}

void hip_dht_queue_rec_free_doall(struct hip_queue *rec)
{
    struct hip_queue *deleted_rec;

    if (hip_dht_queue == NULL || rec == NULL) {
        return;
    }

    /* Check if such element exist, and delete the pointer from
     * the hashtable. */
    deleted_rec = list_del(rec, hip_dht_queue);

    /* Free the memory allocated for the element. */
    if (deleted_rec != NULL) {
        /* We set the memory to '\0' because the user may still have a
         * reference to the memory region that is freed here. */
        memset(deleted_rec, '\0', sizeof(*deleted_rec));
        free(deleted_rec);
        HIP_DEBUG("Queue record deleted.\n");
    }
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_dht_queue_rec_free, struct hip_queue)

void hip_dht_queue_uninit()
{
#ifdef CONFIG_HIP_DHT
    return;
#endif

    if (hip_dht_queue == NULL) {
        return;
    }

    hip_ht_doall(hip_dht_queue,
                 (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(hip_dht_queue_rec_free));
    hip_ht_uninit(hip_dht_queue);
    hip_dht_queue = NULL;
}

/**
 * write_fifo_queue - This function writes data to the hip_queue structure
 *
 * @param write_data data to be written on the queue node
 * @param data_size_in_bytes size of the data sent
 *
 * @return status of the operation 0 on success, -1 on failure
 */
int hip_write_to_dht_queue(void *write_data, int data_size_in_bytes)
{
    void *temp_data            = NULL;
    struct hip_queue *new_item = NULL;
    int err                    = -1;

    _HIP_DEBUG("Write, Items in dht_queue %d on enter\n", dht_queue_count);
    temp_data = malloc(data_size_in_bytes);
    HIP_IFEL((!temp_data), -1, "Failed to malloc memory for data\n");
    memset(temp_data, 0, sizeof(data_size_in_bytes));
    memcpy(temp_data, write_data, data_size_in_bytes);

    new_item           = (struct hip_queue *) malloc(sizeof(struct hip_queue));
    HIP_IFEL((!new_item), -1, "Failed to malloc memory for queue new item\n");
    memset(new_item, 0, sizeof(struct hip_queue));
    new_item->data_len = data_size_in_bytes;
    new_item->data     = temp_data;
    err                = hip_ht_add(hip_dht_queue, new_item);
    dht_queue_count    = dht_queue_count + 1;

    /* Debug line do not leave uncommented */
    //hip_debug_print_dht_queue();
    _HIP_DEBUG("Write, Items in dht_queue %d on exit\n", dht_queue_count);

out_err:
    return err;
}

/**
 * hip_read_from_dht_queue
 *
 * This function writes data to the hip_queue structure
 *
 * @param read_data stores the data read from queue node
 *
 * @return status of the operation 0 on success, -1 on failure
 */
int hip_read_from_dht_queue(void *read_data)
{
    int i                  = 0;
    hip_list_t *item, *tmp;
    struct hip_queue *this = NULL;

    _HIP_DEBUG("Read, Items in dht_queue %d on enter\n", dht_queue_count);

    list_for_each_safe(item, tmp, hip_dht_queue, i) {
        this = (struct hip_queue *) list_entry(item);
        if (this == NULL) {
            return -1;
        }
        memcpy(read_data, this->data, this->data_len);
        _HIP_DEBUG("Node data read: %s \n", (char *) read_data);

        hip_ht_delete(hip_dht_queue, this);
        if (this->data) {
            free(this->data);
        }
        if (this) {
            free(this);
        }

        _HIP_DEBUG("Read, Items in dht_queue %d on exit\n", dht_queue_count);
        dht_queue_count = dht_queue_count - 1;
        // ugly way but I need only one item at a time and this was fast
        return 0;
    }
    /* Debug line do not leave uncommented */
    //hip_debug_print_dht_queue();
    if (this && this->data) {
        free(this->data);
    }
    if (this) {
        free(this);
    }
    return 0;
}

#if 0
/**
 * hip_debug_print_queue
 *
 * This function prints all the dht queue members
 *
 * @ return void
 */
static void hip_debug_print_dht_queue()
{
    int i = 0;
    hip_list_t *item, *tmp;
    struct hip_queue *entry;

    HIP_DEBUG("DEBUGGING QUEUE comment out if left uncommented\n");
    HIP_DEBUG("Head count %d\n", dht_queue_count);
    list_for_each_safe(item, tmp, hip_dht_queue, i) {
        entry = list_entry(item);
        HIP_DEBUG("Node data_len = %d\n", entry->data_len);
        HIP_DEBUG("Node data= %s\n", entry->data);
    }
}

#endif
