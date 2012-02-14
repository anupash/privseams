/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdlib.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"

#include "signaling_cdb.h"


struct hip_ll scdb;


void signaling_cdb_init(void)
{
    hip_ll_init(&scdb);
}

void signaling_cdb_uninit(void)
{
    hip_ll_uninit(&scdb, free);
}

/* Add a connection to the signaling database.
 *
 * @param src_hit   the hit of the local host
 * @param dst_hit   the hit of the peer host
 * @param src_port  the source port of the local host
 * @param dst_port  the destination port of the peer host
 * @param status    the status of the signaling connection
 *
 * @return 0 on success, -1 in case of an error */
int signaling_cdb_add_connection(const struct in6_addr src_hit,
                                 const struct in6_addr dst_hit,
                                 const uint16_t        src_port,
                                 const uint16_t        dst_port,
                                 const int             status)
{
    struct signaling_cdb_entry *entry = malloc(sizeof(struct signaling_cdb_entry));

    if (!entry) {
        HIP_ERROR("Could not allocate memory for new scdb entry\n");
        return -1;
    }

    entry->src_hit  = src_hit;
    entry->dst_hit  = dst_hit;
    entry->src_port = src_port;
    entry->dst_port = dst_port;
    entry->status   = status;

    if (hip_ll_add_last(&scdb, entry)) {
        HIP_ERROR("Failed to add new connection to scdb\n");
        return -1;
    }
    return 0;
}

struct signaling_cdb_entry *signaling_cdb_get_connection(const struct in6_addr src_hit,
                                                         const struct in6_addr dst_hit,
                                                         const uint16_t        src_port,
                                                         const uint16_t        dst_port)
{
    const struct hip_ll_node   *iter  = NULL;
    struct signaling_cdb_entry *entry = NULL;

    while ((iter = hip_ll_iterate(&scdb, iter)) != NULL) {
        entry = (struct signaling_cdb_entry *) iter->ptr;

        HIP_ASSERT(entry != NULL);

        /* depending on whether we were the initiator or responder,
         * src_entry->src_hit may match either src_hit or dst_hit */
        if ((!memcmp(&entry->src_hit, &src_hit, sizeof(struct in6_addr))    &&
             !memcmp(&entry->dst_hit, &dst_hit, sizeof(struct in6_addr))    &&
             entry->src_port == src_port && entry->dst_port == dst_port)    ||
            (!memcmp(&entry->dst_hit, &src_hit, sizeof(struct in6_addr))    &&
             !memcmp(&entry->src_hit, &dst_hit, sizeof(struct in6_addr))    &&
             entry->dst_port == src_port && entry->src_port == dst_port)) {
            return entry;
        }
    }
    return NULL;
}

void signaling_cdb_del_connection(const struct in6_addr src_hit,
                                  const struct in6_addr dst_hit,
                                  const uint16_t        src_port,
                                  const uint16_t        dst_port)
{
    const struct hip_ll_node   *iter  = NULL;
    struct signaling_cdb_entry *entry = NULL;
    int                         index = 0;

    while ((iter = hip_ll_iterate(&scdb, iter)) != NULL) {
        entry = (struct signaling_cdb_entry *) iter->ptr;

        HIP_ASSERT(entry != NULL);

        /* depending on whether we were the initiator or responder,
         * src_entry->src_hit may match either src_hit or dst_hit */
        if ((!memcmp(&entry->src_hit, &src_hit, sizeof(struct in6_addr))    &&
             !memcmp(&entry->dst_hit, &dst_hit, sizeof(struct in6_addr))    &&
             entry->src_port == src_port && entry->dst_port == dst_port)   ||
            (!memcmp(&entry->dst_hit, &src_hit, sizeof(struct in6_addr))    &&
             !memcmp(&entry->src_hit, &dst_hit, sizeof(struct in6_addr))    &&
             entry->dst_port == src_port && entry->src_port == dst_port)) {
            hip_ll_del(&scdb, index, free);
        }
        index++;
    }
}

/* Print the contents of the signaling connection database */
void signaling_cdb_print(void)
{
    const struct hip_ll_node   *iter  = NULL;
    struct signaling_cdb_entry *entry = NULL;

    HIP_DEBUG("------------------ SCDB START ------------------\n");

    while ((iter = hip_ll_iterate(&scdb, iter)) != NULL) {
        entry = (struct signaling_cdb_entry *) iter->ptr;

        HIP_ASSERT(entry != NULL);

        HIP_DEBUG("\t----- SCDB ELEMENT START ------\n");
        HIP_DEBUG_HIT("\tSrc Hit:\t", &entry->src_hit);
        HIP_DEBUG_HIT("\tDst Hit:\t", &entry->dst_hit);
        HIP_DEBUG("\tSrc Port: %u\t\n", entry->src_port);
        HIP_DEBUG("\tDst Port: %u\t\n", entry->dst_port);
        HIP_DEBUG("\tStatus: %i\t\n", entry->status);
        HIP_DEBUG("\t----- SCDB ELEMENT END   ------\n");
    }

    HIP_DEBUG("------------------ SCDB END   ------------------\n");
}
