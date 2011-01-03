/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

#ifndef HIP_MODULES_HIPD_UPDATE_LEGACY_H
#define HIP_MODULES_HIPD_UPDATE_LEGACY_H

#include <stdint.h>
#include <netinet/in.h>

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


struct hip_locator {
    hip_tlv_type_t type;
    hip_tlv_len_t  length;
    /* fixed part ends */
} __attribute__ ((packed));

/**
 * Fixed start of this struct must match to struct hip_peer_addr_list_item
 * for the part of address item. It is used in hip_update_locator_match().
 * @todo Maybe fix this in some better way?
 */
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

int hip_get_locator_addr_item_count(const struct hip_locator *locator);

int hip_create_locators(struct hip_common *locator_msg,
                        struct hip_locator_info_addr_item **locators);

int hip_send_update_to_one_peer(struct hip_common *received_update_packet,
                                struct hip_hadb_state *ha,
                                struct in6_addr *src_addr,
                                struct in6_addr *dst_addr,
                                struct hip_locator_info_addr_item *locators,
                                int type);

int hip_update_init(void);

#endif /* HIP_MODULES_HIPD_UPDATE_LEGACY_H */
