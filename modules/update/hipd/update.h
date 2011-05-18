/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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

/**
 * @file
 * @author  Baris Boyvat <baris#boyvat.com>
 * @version 0.1
 * @date    3.5.2009
 *
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#ifndef HIP_MODULES_UPDATE_HIPD_UPDATE_H
#define HIP_MODULES_UPDATE_HIPD_UPDATE_H

#include <stdint.h>
#include <netinet/in.h>

#include "lib/core/hashtable.h"
#include "lib/core/protodefs.h"

/* the different mobility message types */
#define HIP_UPDATE_LOCATOR              0
#define HIP_UPDATE_ECHO_REQUEST         1
#define HIP_UPDATE_ECHO_RESPONSE        2
#define HIP_UPDATE_ESP_ANCHOR           3
#define HIP_UPDATE_ESP_ANCHOR_ACK       4

/* locator parameter types */
#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1
#define HIP_LOCATOR_LOCATOR_TYPE_UDP     2

enum update_types { UNKNOWN_UPDATE_PACKET, FIRST_UPDATE_PACKET,
                    SECOND_UPDATE_PACKET, THIRD_UPDATE_PACKET };

struct update_state {
    /** A kludge to get the UPDATE retransmission to work.
     *  @todo Remove this kludge. */
    int update_state;

    /** This "linked list" includes the locators we recieved in the initial
     * UPDATE packet. Locators are stored as "struct in6_addr *"s.
     *
     * Hipd sends UPDATE packets including ECHO_REQUESTS to all these
     * addresses.
     *
     * Notice that there's a hack that a hash table is used as a linked list
     * here but this is common allover HIPL and it doesn't seem to cause
     * performance problems.
     */
    HIP_HASHTABLE *addresses_to_send_echo_request;

    /** Stored outgoing UPDATE ID counter. */
    uint32_t update_id_out;
    /** Stored incoming UPDATE ID counter. */
    uint32_t update_id_in;
};

struct hip_locator {
    hip_tlv     type;
    hip_tlv_len length;
    /* fixed part ends */
} __attribute__ ((packed));

struct hip_locator_info_addr_item {
    uint8_t         traffic_type;
    uint8_t         locator_type;
    uint8_t         locator_length;
    uint8_t         reserved; /**< last bit is P (preferred) */
    uint32_t        lifetime;
    struct in6_addr address;
}  __attribute__ ((packed));

/**
 * it is the type 2 locater for UDP or other transport protocol later.
 */
struct hip_locator_info_addr_item2 {
    uint8_t         traffic_type;
    uint8_t         locator_type;
    uint8_t         locator_length;
    uint8_t         reserved; /* last bit is P (preferred) */
    uint32_t        lifetime;
    uint16_t        port;
    uint8_t         transport_protocol;
    uint8_t         kind;
    uint32_t        priority;
    uint32_t        spi;
    struct in6_addr address;
}  __attribute__ ((packed));

/**
 * it is a union of both type1 and type2 locator.
 */
union hip_locator_info_addr {
    struct hip_locator_info_addr_item  type1;
    struct hip_locator_info_addr_item2 type2;
} __attribute__ ((packed));

uint32_t hip_update_get_out_id(const struct update_state *const state);

int hip_trigger_update(struct hip_hadb_state *const hadb_entry);

enum update_types hip_classify_update_type(const struct hip_common *const hip_msg);

int hip_update_init(void);

#endif /* HIP_MODULES_UPDATE_HIPD_UPDATE_H */
