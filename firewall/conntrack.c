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
 * Connection tracker for HIP and ESP. It is inspired by the connection tracker in the Linux kernel. See the following publications for more details:
 * - <a href="http://hipl.hiit.fi/papers/essi_dippa.pdf">E. Vehmersalo, Host Identity Protocol Enabled Firewall: A Prototype Implementation and Analysis, Master's thesis, September 2005</a>
 * - <a href="http://www.usenix.org/events/usenix07/poster.html">Lindqvist, Janne; Vehmersalo, Essi; Komu, Miika; Manner, Jukka, Enterprise Network Packet Filtering for Mobile Cryptographic Identities,
 * Usenix 2007 Annual Technical Conference, Santa Clara, CA, June 20, 2007</a>
 * - Rene Hummen. Secure Identity-based Middlebox Functions using the Host Identity Protocol. Master's thesis, RWTH Aachen, 2009.
 *
 * @brief Connection tracker for HIP and ESP.
 *
 * @author Essi Vehmersalo
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <sys/time.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hostid.h"
#include "lib/core/ife.h"
#include "lib/core/performance.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/tool/pk.h"
#include "modules/update/hipd/update.h"
#include "common_types.h"
#include "dlist.h"
#include "esp_prot_conntrack.h"
#include "firewall_defines.h"
#include "firewall.h"
#include "lib/core/hip_udp.h"
#include "helpers.h"
#include "hslist.h"
#include "pisa.h"
#include "conntrack.h"
#include "config.h"
#include "reinject.h"


struct dlist *hip_list = NULL;
struct dlist *esp_list = NULL;

enum {
    STATE_NEW,
    STATE_ESTABLISHED,
    STATE_ESTABLISHING_FROM_UPDATE,
    STATE_CLOSING
};

int           timeoutChecking = 0;
unsigned long timeoutValue    = 0;

/*------------print functions-------------*/
/**
 * prints out the list of addresses of esp_addr_list
 *
 * @param addr_list list of addresses
 *
 */
static void print_esp_addr_list(const struct slist *addr_list)
{
    const struct slist *list = addr_list;
    struct esp_address *addr = NULL;

    HIP_DEBUG("ESP dst addr list:\n");
    while (list) {
        addr = list->data;
        HIP_DEBUG("addr: %s\n", addr_to_numeric(&addr->dst_addr));
        if (addr && addr->update_id != NULL) {
            HIP_DEBUG("upd id: %d\n", *addr->update_id);
        }
        list = list->next;
    }
    HIP_DEBUG("\n");
}

/**
 * Prints information from a hip_tuple.
 *
 * @param hiptuple HIP tuple
 */
static void print_tuple(const struct hip_tuple *hiptuple)
{
    HIP_DEBUG("next tuple: \n");
    HIP_DEBUG("direction: %i\n", hiptuple->tuple->direction);
    HIP_DEBUG_HIT("src: ", &hiptuple->data->src_hit);
    HIP_DEBUG_HIT("dst: ", &hiptuple->data->dst_hit);
}

/**
 * Prints information from an esp_tuple.
 *
 * @param esp_tuple ESP tuple
 */
static void print_esp_tuple(const struct esp_tuple *esp_tuple)
{
    HIP_DEBUG("esp_tuple: spi:0x%lx new_spi:0x%lx spi_update_id:%0xlx tuple dir:%d\n",
              esp_tuple->spi, esp_tuple->new_spi, esp_tuple->spi_update_id,
              esp_tuple->tuple->direction);

    print_esp_addr_list(esp_tuple->dst_addr_list);
}

/**
 * Prints all tuples in 'esp_list'.
 */
static void print_esp_list(void)
{
    struct dlist *list = esp_list;

    HIP_DEBUG("ESP LIST: \n");
    while (list) {
        if (list->data) {
            print_esp_tuple(list->data);
        }
        list = list->next;
    }
    HIP_DEBUG("\n");
}

/**
 * Prints all tuples in 'hip_list'.
 */
static void print_tuple_list(void)
{
    struct dlist *list = hip_list;

    HIP_DEBUG("TUPLE LIST: \n");
    if (list) {
        while (list) {
            if (list->data) {
                print_tuple(list->data);
            }
            list = list->next;
        }
        HIP_DEBUG("\n");
    } else {
        HIP_DEBUG("NULL\n");
    }
}

/**
 * Test if the given HIT belongs to the local host
 *
 * @param hit the HIT to be tested
 * @return one if the HIT belongs to the local host or zero otherwise
 *
 */
static int hip_fw_hit_is_our(const hip_hit_t *hit)
{
    /* Currently only checks default HIT */
    return !ipv6_addr_cmp(hit, hip_fw_get_default_hit());
}

/*------------tuple handling functions-------------*/

/**
 * forms a data based on the HITs of the packet and returns a hip_data structure
 *
 * @param common a HIP control packet
 * @return struct hip_data corresponding to the HITs of the packet
 */
static struct hip_data *get_hip_data(const struct hip_common *common)
{
    struct hip_data *data = NULL;

    // init hip_data for this tuple
    data = calloc(1, sizeof(struct hip_data));

    memcpy(&data->src_hit, &common->hits, sizeof(struct in6_addr));
    memcpy(&data->dst_hit, &common->hitr, sizeof(struct in6_addr));

    return data;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
/**
 * Replace the pseudo HITs in opportunistic entries with real HITs (once
 * the real HITs are known from the R1 packet)
 *
 * @param data hip_data data structure
 * @param ip6_from the IP address from which the packet arrived from
 *
 */
static void update_peer_opp_info(const struct hip_data *data,
                                 const struct in6_addr *ip6_from)
{
    struct dlist *list = (struct dlist *) hip_list;
    hip_hit_t     phit;

    HIP_DEBUG("updating opportunistic entries\n");
    /* the pseudo hit is compared with the hit in the entries */
    hip_opportunistic_ipv6_to_hit(ip6_from, &phit, HIP_HIT_TYPE_HASH100);

    while (list) {
        struct hip_tuple *tuple = list->data;

        if (IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->src_hit) &&
            IN6_ARE_ADDR_EQUAL(&phit, &tuple->data->dst_hit)) {
            ipv6_addr_copy(&tuple->data->dst_hit, &data->src_hit);
        }
        if (IN6_ARE_ADDR_EQUAL(&phit, &tuple->data->src_hit) &&
            IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->dst_hit)) {
            ipv6_addr_copy(&tuple->data->src_hit, &data->src_hit);
        }
        list = list->next;
    }
    return;
}

#endif

/** Fetch a hip_tuple from the connection table.
 *
 * @param data packet information constructed from the packet
 * @param type_hdr HIP control packet type (HIP_I1 etc)
 * @param ip6_from the source address of the control packet
 * @return the tuple or NULL, if not found.
 */
static struct tuple *get_tuple_by_hip(const struct hip_data *data,
                                      OPP const uint8_t type_hdr,
                                      OPP const struct in6_addr *ip6_from)
{
    struct hip_tuple *tuple = NULL;
    struct dlist     *list  = hip_list;

    while (list) {
        tuple = list->data;

        if (IN6_ARE_ADDR_EQUAL(&data->src_hit, &tuple->data->src_hit) &&
            IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->dst_hit)) {
            HIP_DEBUG("connection found, \n");
            return tuple->tuple;
        }
        list = list->next;
    }

#ifdef CONFIG_HIP_OPPORTUNISTIC
    /* In the case the entry was not found, place the real peer HIT in
     * the entries if the HIT happened to be an opportunistic one */
    if (type_hdr == HIP_R1) {
        update_peer_opp_info(data, ip6_from);
        return get_tuple_by_hip(data, -1, ip6_from);
    }
#endif

    HIP_DEBUG("get_tuple_by_hip: no connection found\n");
    return NULL;
}

/**
 * Find an entry from the given list that matches to the given address
 *
 * @param addr_list the list to be searched for
 * @param addr the address to matched from the list
 * @return the entry from the list that matched to the given address, or NULL if not found
 */
static struct esp_address *get_esp_address(const struct slist *addr_list,
                                           const struct in6_addr *addr)
{
    const struct slist *list     = addr_list;
    struct esp_address *esp_addr = NULL;

    HIP_DEBUG("get_esp_address\n");

    while (list) {
        esp_addr = list->data;
        HIP_DEBUG("addr: %s \n", addr_to_numeric(&esp_addr->dst_addr));

        HIP_DEBUG_HIT("111", &esp_addr->dst_addr);
        HIP_DEBUG_HIT("222", addr);

        if (IN6_ARE_ADDR_EQUAL(&esp_addr->dst_addr, addr)) {
            HIP_DEBUG("addr found\n");
            return esp_addr;
        }
        list = list->next;
    }
    HIP_DEBUG("get_esp_address: addr %s not found\n", addr_to_numeric(addr));
    return NULL;
}

/**
 * Insert an address into a list of addresses. If same address exists already,
 * the update_id is replaced with the new value.
 *
 * @param addr_list the address list
 * @param addr the address to be added
 * @param upd_id update id
 *
 * @return the address list
 */
static struct slist *update_esp_address(struct slist *addr_list,
                                        const struct in6_addr *addr,
                                        const uint32_t *upd_id)
{
    struct esp_address *esp_addr = get_esp_address(addr_list, addr);
    HIP_DEBUG("update_esp_address: address: %s \n", addr_to_numeric(addr));

    if (!addr_list) {
        HIP_DEBUG("Esp slist is empty\n");
    }
    if (esp_addr != NULL) {
        if (upd_id != NULL) {
            if (esp_addr->update_id == NULL) {
                esp_addr->update_id = malloc(sizeof(uint32_t));
            }
            *esp_addr->update_id = *upd_id;
        }
        HIP_DEBUG("update_esp_address: found and updated\n");
        return addr_list;
    }
    esp_addr = malloc(sizeof(struct esp_address));
    memcpy(&esp_addr->dst_addr, addr, sizeof(struct in6_addr));
    if (upd_id != NULL) {
        esp_addr->update_id  = malloc(sizeof(uint32_t));
        *esp_addr->update_id = *upd_id;
    } else {
        esp_addr->update_id = NULL;
    }
    HIP_DEBUG("update_esp_address: addr created and added\n");
    return append_to_slist(addr_list, esp_addr);
}

/**
 * Find esp tuple from esp_list that matches the argument spi and contains the
 * argument ip address
 *
 * @param dst_addr the optional destination address to be searched for
 * @param spi the SPI number to be searched for
 * @return a tuple matching to the address and SPI or NULL if not found
 */
static struct tuple *get_tuple_by_esp(const struct in6_addr *dst_addr, const uint32_t spi)
{
    struct slist *list = (struct slist *) esp_list;

    if (!list) {
        HIP_DEBUG("Esp tuple list is empty\n");
    }
    while (list) {
        struct esp_tuple *tuple = list->data;
        if (spi == tuple->spi) {
            if (dst_addr && get_esp_address(tuple->dst_addr_list, dst_addr) != NULL) {
                HIP_DEBUG("connection found by esp\n");
                return tuple->tuple;
            } else if (!dst_addr) {
                return tuple->tuple;
            }
        }
        list = list->next;
    }

    HIP_DEBUG("get_tuple_by_esp: dst addr %s spi 0x%lx no connection found\n",
              (dst_addr ? addr_to_numeric(dst_addr) : "NULL"), spi);

    return NULL;
}

/**
 * find esp_tuple from a list that matches the argument spi value
 *
 * @param search_list the list to be searched for
 * @param spi the SPI number to the matched from the list
 * @return the matching ESP tuple or NULL if not found
 */
struct esp_tuple *find_esp_tuple(const struct slist *search_list,
                                 const uint32_t spi)
{
    const struct slist *list      = search_list;
    struct esp_tuple   *esp_tuple = NULL;

    if (!list) {
        HIP_DEBUG("Esp tuple slist is empty\n");
    }
    while (list) {
        esp_tuple = list->data;
        if (esp_tuple->spi == spi) {
            HIP_DEBUG("find_esp_tuple: Found esp_tuple with spi 0x%lx\n", spi);
            return esp_tuple;
        }
        list = list->next;
    }
    return NULL;
}

/**
 * initialize and store a new HIP/ESP connnection into the connection table
 *
 * @param data the connection-related data to be inserted
 * @see remove_connection
 */
static void insert_new_connection(const struct hip_data *data)
{
    struct connection *connection = NULL;

    HIP_DEBUG("insert_new_connection\n");

    connection = calloc(1, sizeof(struct connection));

    connection->state = STATE_ESTABLISHED;
    //set time stamp
    gettimeofday(&connection->time_stamp, NULL);
#ifdef HIP_CONFIG_MIDAUTH
    connection->pisa_state = PISA_STATE_DISALLOW;
#endif

    //original direction tuple
    connection->original.state                    = HIP_STATE_UNASSOCIATED;
    connection->original.direction                = ORIGINAL_DIR;
    connection->original.esp_tuples               = NULL;
    connection->original.connection               = connection;
    connection->original.hip_tuple                = malloc(sizeof(struct hip_tuple));
    connection->original.hip_tuple->tuple         = &connection->original;
    connection->original.hip_tuple->data          = calloc(1, sizeof(struct hip_data));
    connection->original.hip_tuple->data->src_hit = data->src_hit;
    connection->original.hip_tuple->data->dst_hit = data->dst_hit;

    //reply direction tuple
    connection->reply.state                    = HIP_STATE_UNASSOCIATED;
    connection->reply.direction                = REPLY_DIR;
    connection->reply.esp_tuples               = NULL;
    connection->reply.connection               = connection;
    connection->reply.hip_tuple                = malloc(sizeof(struct hip_tuple));
    connection->reply.hip_tuple->tuple         = &connection->reply;
    connection->reply.hip_tuple->data          = calloc(1, sizeof(struct hip_data));
    connection->reply.hip_tuple->data->src_hit = data->dst_hit;
    connection->reply.hip_tuple->data->dst_hit = data->src_hit;

    //add tuples to list
    hip_list = append_to_list(hip_list, connection->original.hip_tuple);
    hip_list = append_to_list(hip_list, connection->reply.hip_tuple);
    HIP_DEBUG("inserting connection \n");
}

/**
 * Insert a new ESP tuple to the connection tracker
 *
 * @param esp_tuple the ESP tuple to be inserted
 */
static void insert_esp_tuple(struct esp_tuple *esp_tuple)
{
    esp_list = append_to_list(esp_list, esp_tuple);

    HIP_DEBUG("insert_esp_tuple:\n");
    print_esp_list();
}

/**
 * deallocate memory of a compound hip_tuple structure with all of its pointers
 *
 * @param hip_tuple the hip tuple to be freed
 */
static void free_hip_tuple(struct hip_tuple *hip_tuple)
{
    if (hip_tuple) {
        if (hip_tuple->data) {
            // free keys depending on cipher
            if (hip_tuple->data->src_pub_key && hip_tuple->data->src_hi) {
                switch (hip_get_host_id_algo(hip_tuple->data->src_hi)) {
                case HIP_HI_RSA:
                    RSA_free(hip_tuple->data->src_pub_key);
                    break;
                case HIP_HI_DSA:
                    DSA_free(hip_tuple->data->src_pub_key);
                    break;
                default:
                    HIP_DEBUG("Could not free public key, because key type is unknown.\n");
                }
            }

            free(hip_tuple->data->src_hi);

            free(hip_tuple->data);
            hip_tuple->data = NULL;
        }

        hip_tuple->tuple = NULL;
        free(hip_tuple);
    }
}

/**
 * deallocate an esp_tuple structure along with all of its pointers
 *
 * @param esp_tuple the ESP tuple to be freed
 */
static void free_esp_tuple(struct esp_tuple *esp_tuple)
{
    if (esp_tuple) {
        struct slist       *list = esp_tuple->dst_addr_list;
        struct esp_address *addr = NULL;

        // remove eventual cached anchor elements for this esp tuple
        esp_prot_conntrack_remove_state(esp_tuple);

        // remove all associated addresses
        while (list) {
            esp_tuple->dst_addr_list = remove_link_slist(esp_tuple->dst_addr_list,
                                                         list);
            addr = list->data;

            free(addr->update_id);
            free(addr);
            list = esp_tuple->dst_addr_list;
        }

        esp_tuple->tuple = NULL;
        free(esp_tuple);
    }
}

/**
 * deallocate dynamically allocated parts of a tuple along with its associated HIP and ESP tuples
 *
 * @param tuple the tuple to be freed
 */
static void remove_tuple(struct tuple *tuple)
{
    if (tuple) {
        // remove hip_tuple from helper list
        hip_list = remove_link_dlist(hip_list,
                                     find_in_dlist(hip_list, tuple->hip_tuple));
        // now free hip_tuple and its members
        free_hip_tuple(tuple->hip_tuple);
        tuple->hip_tuple = NULL;

        struct slist *list = tuple->esp_tuples;
        while (list) {
            // remove esp_tuples from helper list
            esp_list = remove_link_dlist(esp_list,
                                         find_in_dlist(esp_list, list->data));

            tuple->esp_tuples = remove_link_slist(tuple->esp_tuples, list);
            free_esp_tuple(list->data);
            list->data = NULL;
            free(list);
            list = tuple->esp_tuples;
        }
        tuple->esp_tuples = NULL;
        tuple->connection = NULL;

        // tuple was not malloced -> no free here
        free(tuple->src_ip);
        tuple->src_ip = NULL;

        free(tuple->dst_ip);
        tuple->dst_ip = NULL;
    }
}

/**
 * removes a connection (both way tuples) along with its associated HIP and ESP tuples
 *
 * @param connection the connection to be freed
 * @see insert_new_connection
 */
static void remove_connection(struct connection *connection)
{
    HIP_DEBUG("remove_connection: tuple list before: \n");
    print_tuple_list();

    HIP_DEBUG("remove_connection: esp list before: \n");
    print_esp_list();

    if (connection) {
        remove_tuple(&connection->original);
        remove_tuple(&connection->reply);

        free(connection);
    }

    HIP_DEBUG("remove_connection: tuple list after: \n");
    print_tuple_list();

    HIP_DEBUG("remove_connection: esp list after: \n");
    print_esp_list();
}

/**
 * create new ESP tuple based on the given parameters
 *
 * @param esp_info a pointer to the ESP info parameter in the control message
 * @param locator a pointer to the locator
 * @param seq a pointer to the sequence number
 * @param tuple a pointer to the corresponding tuple
 * @return the created tuple (caller frees) or NULL on failure (e.g. SPIs do not match)
 */
static struct esp_tuple *esp_tuple_from_esp_info_locator(const struct hip_esp_info *esp_info,
                                                         const struct hip_locator *locator,
                                                         const struct hip_seq *seq,
                                                         struct tuple *tuple)
{
    struct esp_tuple                        *new_esp      = NULL;
    const struct hip_locator_info_addr_item *locator_addr = NULL;
    int                                      n            = 0;

    if (esp_info && locator && esp_info->new_spi == esp_info->old_spi) {
        HIP_DEBUG("esp_tuple_from_esp_info_locator: new spi 0x%lx\n", esp_info->new_spi);
        /* check that old spi is found */
        new_esp        = calloc(1, sizeof(struct esp_tuple));
        new_esp->spi   = ntohl(esp_info->new_spi);
        new_esp->tuple = tuple;

        n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator)) /
            sizeof(struct hip_locator_info_addr_item);
        HIP_DEBUG("esp_tuple_from_esp_info_locator: %d addresses in locator\n", n);
        if (n > 0) {
            locator_addr = (const struct hip_locator_info_addr_item *)
                           (locator + 1);
            while (n > 0) {
                struct esp_address *esp_address = malloc(sizeof(struct esp_address));
                memcpy(&esp_address->dst_addr,
                       &locator_addr->address,
                       sizeof(struct in6_addr));
                esp_address->update_id  = malloc(sizeof(uint32_t));
                *esp_address->update_id = seq->update_id;
                new_esp->dst_addr_list  = append_to_slist(new_esp->dst_addr_list,
                                                          esp_address);
                n--;
                if (n > 0) {
                    locator_addr++;
                }
            }
        } else {
            free(new_esp);
            new_esp = NULL;
        }
    }
    return new_esp;
}

/**
 * create a new esp_tuple from the given parameters
 *
 * @param esp_info a pointer to an ESP info parameter in the control message
 * @param addr a pointer to an address
 * @param tuple a pointer to a tuple structure
 * @return the created ESP tuple (caller frees) or NULL on failure (e.g. SPIs don't match)
 */
static struct esp_tuple *esp_tuple_from_esp_info(const struct hip_esp_info *esp_info,
                                                 const struct in6_addr *addr,
                                                 struct tuple *tuple)
{
    struct esp_tuple *new_esp = NULL;
    if (esp_info) {
        new_esp        = calloc(1, sizeof(struct esp_tuple));
        new_esp->spi   = ntohl(esp_info->new_spi);
        new_esp->tuple = tuple;

        struct esp_address *esp_address = malloc(sizeof(struct esp_address));

        memcpy(&esp_address->dst_addr, addr, sizeof(struct in6_addr));

        esp_address->update_id = NULL;
        new_esp->dst_addr_list = append_to_slist(new_esp->dst_addr_list,
                                                 esp_address);
    }
    return new_esp;
}

/**
 * initialize and insert connection based on the given parameters from UPDATE packet
 *
 * @param data a pointer a HIP data structure
 * @param esp_info a pointer to an ESP info data structure
 * @param locator a pointer to a locator
 * @param seq a pointer to a sequence number
 *
 * returns 1 if succesful 0 otherwise (latter does not occur currently)
 */
static int insert_connection_from_update(const struct hip_data *data,
                                         const struct hip_esp_info *esp_info,
                                         const struct hip_locator *locator,
                                         const struct hip_seq *seq)
{
    struct connection *connection = malloc(sizeof(struct connection));
    struct esp_tuple  *esp_tuple  = NULL;

    esp_tuple = esp_tuple_from_esp_info_locator(esp_info, locator, seq,
                                                &connection->reply);
    if (esp_tuple == NULL) {
        free(connection);
        HIP_DEBUG("insert_connection_from_update: can't create connection\n");
        return 0;
    }
    connection->state = STATE_ESTABLISHING_FROM_UPDATE;
#ifdef HIP_CONFIG_MIDAUTH
    connection->pisa_state = PISA_STATE_DISALLOW;
#endif

    //original direction tuple
    connection->original.state                    = HIP_STATE_UNASSOCIATED;
    connection->original.direction                = ORIGINAL_DIR;
    connection->original.esp_tuples               = NULL;
    connection->original.connection               = connection;
    connection->original.hip_tuple                = malloc(sizeof(struct hip_tuple));
    connection->original.hip_tuple->tuple         = &connection->original;
    connection->original.hip_tuple->data          = malloc(sizeof(struct hip_data));
    connection->original.hip_tuple->data->src_hit = data->src_hit;
    connection->original.hip_tuple->data->dst_hit = data->dst_hit;
    connection->original.hip_tuple->data->src_hi  = NULL;
    connection->original.hip_tuple->data->verify  = NULL;


    //reply direction tuple
    connection->reply.state     = HIP_STATE_UNASSOCIATED;
    connection->reply.direction = REPLY_DIR;

    connection->reply.esp_tuples = NULL;
    connection->reply.esp_tuples = append_to_slist(connection->reply.esp_tuples,
                                                   esp_tuple);
    insert_esp_tuple(esp_tuple);

    connection->reply.connection               = connection;
    connection->reply.hip_tuple                = malloc(sizeof(struct hip_tuple));
    connection->reply.hip_tuple->tuple         = &connection->reply;
    connection->reply.hip_tuple->data          = malloc(sizeof(struct hip_data));
    connection->reply.hip_tuple->data->src_hit = data->dst_hit;
    connection->reply.hip_tuple->data->dst_hit = data->src_hit;
    connection->reply.hip_tuple->data->src_hi  = NULL;
    connection->reply.hip_tuple->data->verify  = NULL;



    //add tuples to list
    hip_list = append_to_list(hip_list, connection->original.hip_tuple);
    hip_list = append_to_list(hip_list, connection->reply.hip_tuple);
    HIP_DEBUG("insert_connection_from_update \n");
    return 1;
}

/**
 * Hipfw has an experimental mode which allows it to act as an ESP
 * Relay to pass e.g.  p2p-unfriendly NAT boxes. The ESP relay mode
 * assumes that the HIP relay (in hipd) and ESP relay (in hipfw) are
 * running on the same middlehost in a public network. The responder
 * has to register to the relay with "hipconf add server full-relay"
 * which operates as defined in <a
 * href="http://tools.ietf.org/html/draft-ietf-hip-nat-traversal"> NAT
 * traversal for HIP</a>. Then the initiator can contact the responder
 * through the IP address of the HIP/ESP relay. The relay acts as a two-way
 * NAT and hides the addresses of the initiator and responder. This way,
 * the the relay supports P2P-unfriendly NAT traversal with the cost of
 * triangular routing. If the initiator and responder wish to communicate
 * with each other directly, they can exchange locators either in base exchange
 * or UPDATE.
 *
 * @todo implement the same handling for UPDATE
 *
 * @param common the R2 packet
 * @param ctx packet context
 *
 * @return zero on success and non-zero on error
 */
static int hipfw_handle_relay_to_r2(const struct hip_common *common,
                                    const struct hip_fw_context *ctx)
{
    struct iphdr              *iph      = (struct iphdr *) ctx->ipq_packet->payload;
    const struct hip_relay_to *relay_to = NULL; /* same format as relay_from */
    struct tuple              *tuple, *reverse_tuple;
    int                        err = 0;
    uint32_t                   spi;
    const struct hip_esp_info *esp_info;

    HIP_DEBUG_IN6ADDR("ctx->src", &ctx->src);
    HIP_DEBUG_IN6ADDR("ctx->dst", &ctx->dst);

    HIP_ASSERT((hip_get_msg_type(common) == HIP_R2));

    HIP_IFEL(!(relay_to = hip_get_param(common, HIP_PARAM_RELAY_TO)), -1,
             "No relay_to, skip\n");

    HIP_DEBUG_IN6ADDR("relay_to_addr", &relay_to->address);

    HIP_IFEL(!((ctx->ip_version == 4) &&
               (iph->protocol == IPPROTO_UDP)), 0,
             "Not a relay packet, ignore\n");

    HIP_IFEL(ipv6_addr_cmp(&ctx->dst, &relay_to->address) == 0, 0,
             "Reinjected control packet, passing it\n");

    esp_info = hip_get_param(common, HIP_PARAM_ESP_INFO);
    HIP_IFEL(!esp_info, 0, "No ESP_INFO, pass\n");
    spi = ntohl(esp_info->new_spi);

    HIP_DEBUG("SPI is 0x%lx\n", spi);

    HIP_IFEL(!(tuple = get_tuple_by_esp(NULL, spi)), 0,
             "No tuple, skip\n");

    HIP_IFEL(!(reverse_tuple = get_tuple_by_hits(&common->hits, &common->hitr)), 0,
             "No reverse tuple, skip\n");

    HIP_DEBUG("tuple src=%d dst=%d\n", tuple->src_port, tuple->dst_port);
    HIP_DEBUG_IN6ADDR("tuple src ip", tuple->src_ip);
    HIP_DEBUG_IN6ADDR("tuple dst ip", tuple->dst_ip);
    HIP_DEBUG("tuple dir=%d, sport=%d, dport=%d, rel=%d\n", tuple->direction,
              tuple->src_port, tuple->dst_port, tuple->esp_relay);

    HIP_DEBUG("reverse tuple src=%d dst=%d\n", reverse_tuple->src_port,
              reverse_tuple->dst_port);
    HIP_DEBUG_IN6ADDR("reverse tuple src ip", reverse_tuple->src_ip);
    HIP_DEBUG_IN6ADDR("reverse tuple dst ip", reverse_tuple->dst_ip);
    HIP_DEBUG("reverse tuple dir=%d, sport=%d, dport=%d, rel=%d\n",
              reverse_tuple->direction, reverse_tuple->src_port,
              reverse_tuple->dst_port, reverse_tuple->esp_relay);

    /* Store Responder's IP address and port */
    tuple->esp_relay = 1;
    ipv6_addr_copy(&tuple->esp_relay_daddr, &ctx->src);
    tuple->esp_relay_dport = tuple->dst_port;
    HIP_DEBUG("tuple relay port=%d\n", tuple->esp_relay_dport);
    HIP_DEBUG_IN6ADDR("tuple relay ip", &tuple->esp_relay_daddr);

    /* Store Initiator's IP address and port */
    reverse_tuple->esp_relay = 1;
    ipv6_addr_copy(&reverse_tuple->esp_relay_daddr, &relay_to->address);
    reverse_tuple->esp_relay_dport = ntohs(relay_to->port);
    HIP_DEBUG("reverse_tuple relay port=%d\n", reverse_tuple->esp_relay_dport);
    HIP_DEBUG_IN6ADDR("reverse_tuple relay ip", &reverse_tuple->esp_relay_daddr);

out_err:
    return 0;
}

/**
 * Process an R1 packet. This function also stores the HI of the Responder
 * to be able to verify signatures also later. The HI is stored only if the
 * signature in R1 was valid.
 *
 * @param common the R1 packet
 * @param tuple the corresponding connection tuple
 * @param verify_responder currently unused
 * @param ctx the context
 *
 * @return one if the packet was ok or zero otherwise
 */

// first check signature then store hi
static int handle_r1(struct hip_common *common, struct tuple *tuple,
                     DBG int verify_responder,
                     UNUSED const struct hip_fw_context *ctx)
{
    struct in6_addr           hit;
    const struct hip_host_id *host_id = NULL;
    // assume correct packet
    int         err = 1;
    hip_tlv_len len = 0;

    HIP_DEBUG("verify_responder: %i\n", verify_responder);

    // handling HOST_ID param
    HIP_IFEL(!(host_id = hip_get_param(common, HIP_PARAM_HOST_ID)),
             -1, "No HOST_ID found in control message\n");

    len = hip_get_param_total_len(host_id);

    HIP_DEBUG("verifying hi -> hit mapping...\n");

    /* we have to calculate the hash ourselves to check the
     * hi -> hit mapping */
    hip_host_id_to_hit(host_id, &hit, HIP_HIT_TYPE_HASH100);

    // match received hit and calculated hit
    HIP_IFEL(ipv6_addr_cmp(&hit, &tuple->hip_tuple->data->src_hit), 0,
             "HI -> HIT mapping does NOT match\n");
    HIP_INFO("HI -> HIT mapping verified\n");

    HIP_DEBUG("verifying signature...\n");

    // init hi parameter and copy
    HIP_IFEL(!(tuple->hip_tuple->data->src_hi = malloc(len)),
             -ENOMEM, "Out of memory\n");
    memcpy(tuple->hip_tuple->data->src_hi, host_id, len);

    // store the public key separately
    // store function pointer for verification
    switch (hip_get_host_id_algo(tuple->hip_tuple->data->src_hi)) {
    case HIP_HI_RSA:
        tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_rsa((const struct hip_host_id_priv *) host_id, 0);
        tuple->hip_tuple->data->verify      = hip_rsa_verify;
        break;
    case HIP_HI_DSA:
        tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_dsa((const struct hip_host_id_priv *) host_id, 0);
        tuple->hip_tuple->data->verify      = hip_dsa_verify;
        break;
    default:
        HIP_ERROR("Could not store public key from I2, because host id algorithm is unknown.\n");
        err = -1;
        goto out_err;
    }

    HIP_IFEL(tuple->hip_tuple->data->verify(tuple->hip_tuple->data->src_pub_key, common),
             -EINVAL, "Verification of signature failed\n");

    HIP_DEBUG("verified R1 signature\n");

    // check if the R1 contains ESP protection transforms
    HIP_IFEL(esp_prot_conntrack_R1_tfms(common, tuple), -1,
             "failed to track esp protection extension transforms\n");

out_err:
    return err;
}

/**
 * Process an I2 packet. If connection already exists, the esp tuple is just
 * added to the existing connection. This occurs, for example, when connection
 * is re-established. In such a case, the old ESP tuples are not removed. If an
 * attacker spoofs an I2 or R2, the valid peers are still able to send data.
 *
 * @param common the I2 packet
 * @param tuple the connection tracking tuple corresponding to the I2 packet
 * @param ctx packet context
 *
 * @return one on success or zero failure
 */
static int handle_i2(struct hip_common *common, struct tuple *tuple,
                     const struct hip_fw_context *ctx)
{
    const struct hip_esp_info *spi            = NULL;
    const struct slist        *other_dir_esps = NULL;
    const struct hip_host_id  *host_id        = NULL;
    struct tuple              *other_dir      = NULL;
    struct esp_tuple          *esp_tuple      = NULL;
    struct in6_addr            hit;
    // assume correct packet
    int                    err     = 1;
    hip_tlv_len            len     = 0;
    const struct in6_addr *ip6_src = &ctx->src;

    HIP_DEBUG("\n");

    HIP_IFEL(!(spi = hip_get_param(common, HIP_PARAM_ESP_INFO)),
             0, "no spi found\n");

    host_id = hip_get_param(common, HIP_PARAM_HOST_ID);

    // handling HOST_ID param
    if (host_id) {
        len = hip_get_param_total_len(host_id);

        // verify HI->HIT mapping
        HIP_IFEL(hip_host_id_to_hit(host_id, &hit, HIP_HIT_TYPE_HASH100) ||
                 ipv6_addr_cmp(&hit, &tuple->hip_tuple->data->src_hit),
                 -1, "Unable to verify HOST_ID mapping to src HIT\n");

        // init hi parameter and copy
        HIP_IFEL(!(tuple->hip_tuple->data->src_hi = malloc(len)),
                 -ENOMEM, "Out of memory\n");
        memcpy(tuple->hip_tuple->data->src_hi, host_id, len);

        // store the public key separately
        // store function pointer for verification
        switch (hip_get_host_id_algo(tuple->hip_tuple->data->src_hi)) {
        case HIP_HI_RSA:
            tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_rsa((const struct hip_host_id_priv *) host_id, 0);
            tuple->hip_tuple->data->verify      = hip_rsa_verify;
            break;
        case HIP_HI_DSA:
            tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_dsa((const struct hip_host_id_priv *) host_id, 0);
            tuple->hip_tuple->data->verify      = hip_dsa_verify;
            break;
        default:
            HIP_ERROR("Could not store public key from I2, because host id algorithm is unknown.\n");
            err = -1;
            goto out_err;
        }

        HIP_IFEL(tuple->hip_tuple->data->verify(tuple->hip_tuple->data->src_pub_key, common),
                 -EINVAL, "Verification of signature failed\n");

        HIP_DEBUG("verified I2 signature\n");
    } else {
        HIP_DEBUG("No HOST_ID found in control message\n");
    }

    // TODO: clean up
    // TEST
    if (tuple->direction == ORIGINAL_DIR) {
        other_dir      = &tuple->connection->reply;
        other_dir_esps = tuple->connection->reply.esp_tuples;
    } else {
        other_dir      = &tuple->connection->original;
        other_dir_esps = tuple->connection->original.esp_tuples;
    }

    // try to look up esp_tuple for this connection
    esp_tuple = find_esp_tuple(other_dir_esps, ntohl(spi->new_spi));
    if (!esp_tuple) {
        // esp_tuple does not exist yet
        HIP_IFEL(!(esp_tuple = calloc(1, sizeof(struct esp_tuple))), 0,
                 "failed to allocate memory\n");

        esp_tuple->spi           = ntohl(spi->new_spi);
        esp_tuple->new_spi       = 0;
        esp_tuple->spi_update_id = 0;
        esp_tuple->dst_addr_list = NULL;
        esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
                                                      ip6_src, NULL);
        esp_tuple->tuple = other_dir;

        other_dir->esp_tuples = append_to_slist(other_dir->esp_tuples, esp_tuple);

        insert_esp_tuple(esp_tuple);
    }

    // TEST_END

    /* check if the I2 contains ESP protection anchor and store state */
    HIP_IFEL(esp_prot_conntrack_I2_anchor(common, tuple), -1,
             "failed to track esp protection extension state\n");

out_err:
    return err;
}

/**
 * Process an R2 packet. If connection already exists, the esp tuple is
 * just added to the existing connection. This occurs, for example, when
 * the connection is re-established. In such a case, the old esp
 * tuples are not removed. If an attacker spoofs an I2 or R2, the
 * valid peers are still able to send data.
 *
 * @param common the R2 packet
 * @param tuple the connection tracking tuple corresponding to the R2 packet
 * @param ctx packet context
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_r2(const struct hip_common *common, struct tuple *tuple,
                     const struct hip_fw_context *ctx)
{
    const struct hip_esp_info *spi            = NULL;
    struct tuple              *other_dir      = NULL;
    struct slist              *other_dir_esps = NULL;
    struct esp_tuple          *esp_tuple      = NULL;
    const struct in6_addr     *ip6_src        = &ctx->src;
    int                        err            = 1;

    HIP_IFEL(!(spi = hip_get_param(common, HIP_PARAM_ESP_INFO)),
             0, "no spi found\n");

    // TODO: clean up
    // TEST
    if (tuple->direction == ORIGINAL_DIR) {
        other_dir      = &tuple->connection->reply;
        other_dir_esps = tuple->connection->reply.esp_tuples;
    } else {
        other_dir      = &tuple->connection->original;
        other_dir_esps = tuple->connection->original.esp_tuples;
    }

    // try to look up esp_tuple for this connection
    if (!(esp_tuple = find_esp_tuple(other_dir_esps, ntohl(spi->new_spi)))) {
        if (!(esp_tuple = esp_prot_conntrack_R2_esp_tuple(other_dir_esps))) {
            HIP_IFEL(!(esp_tuple = calloc(1, sizeof(struct esp_tuple))), 0,
                     "failed to allocate memory\n");

            //add esp_tuple to list of tuples
            other_dir->esp_tuples = append_to_slist(other_dir->esp_tuples,
                                                    esp_tuple);
        }

        // this also has to be set in esp protection extension case
        esp_tuple->spi           = ntohl(spi->new_spi);
        esp_tuple->new_spi       = 0;
        esp_tuple->spi_update_id = 0;
        esp_tuple->dst_addr_list = NULL;
        esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
                                                      ip6_src, NULL);
        esp_tuple->tuple = other_dir;

        insert_esp_tuple(esp_tuple);

        HIP_DEBUG("ESP tuple inserted\n");
    } else {
        HIP_DEBUG("ESP tuple already exists!\n");
    }

    /* check if the R2 contains ESP protection anchor and store state */
    HIP_IFEL(esp_prot_conntrack_R2_anchor(common, tuple), -1,
             "failed to track esp protection extension state\n");

    // TEST_END

    if (esp_relay && ctx->udp_encap_hdr) {
        HIP_IFEL(hipfw_handle_relay_to_r2(common, ctx),
                 -1, "handling of relay_to failed\n");
    }

out_err:
    return err;
}

/**
 * Update an existing ESP tuple according to the given parameters Argument
 * esp_info or locator may be null. SPI or ip_addr will not be updated in that case.
 *
 * @param esp_info a pointer to the ESP info parameter in the control message
 * @param locator a pointer to the locator
 * @param seq a pointer to the sequence number
 * @param esp_tuple a pointer to the ESP tuple to be updated
 *
 * @return 1 if successful, or 0 otherwise
 */
static int update_esp_tuple(const struct hip_esp_info *esp_info,
                            const struct hip_locator *locator,
                            const struct hip_seq *seq,
                            struct esp_tuple *esp_tuple)
{
    const struct hip_locator_info_addr_item *locator_addr = NULL;
    int                                      err          = 1;
    int                                      n            = 0;

    HIP_DEBUG("\n");

    if (esp_info && locator && seq) {
        HIP_DEBUG("esp_info, locator and seq, \n");

        if (ntohl(esp_info->old_spi) != esp_tuple->spi
            || ntohl(esp_info->new_spi) != ntohl(esp_info->old_spi)) {
            HIP_DEBUG("update_esp_tuple: spi no match esp_info old:0x%lx tuple:0x%lx locator:%d\n",
                      ntohl(esp_info->old_spi), esp_tuple->spi, ntohl(esp_info->new_spi));

            err = 0;
            goto out_err;
        }

        esp_tuple->new_spi       = ntohl(esp_info->new_spi);
        esp_tuple->spi_update_id = seq->update_id;

        n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator))
            / sizeof(struct hip_locator_info_addr_item);

        if (n < 1) {
            HIP_DEBUG("no locator param found\n");

            err = 0;             // no param found
            goto out_err;
        }

        locator_addr = (const struct hip_locator_info_addr_item *)
                       (locator + 1);

        while (n > 0) {
            esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
                                                          &locator_addr->address,
                                                          &seq->update_id);
            n--;

            if (n > 0) {
                locator_addr++;
            }
        }
    } else if (esp_info && seq) {
        HIP_DEBUG("esp_info and seq, ");

        if (ntohl(esp_info->old_spi) != esp_tuple->spi) {
            HIP_DEBUG("update_esp_tuple: esp_info spi no match esp_info:0x%lx tuple:0x%lx\n",
                      ntohl(esp_info->old_spi), esp_tuple->spi);

            err = 0;
            goto out_err;
        }

        esp_tuple->new_spi       = ntohl(esp_info->new_spi);
        esp_tuple->spi_update_id = seq->update_id;
    } else if (locator && seq) {
        HIP_DEBUG("locator and seq, ");

        if (ntohl(esp_info->new_spi) != esp_tuple->spi) {
            HIP_DEBUG("esp_info spi no match esp_info:0x%lx tuple: 0x%lx\n",
                      ntohl(esp_info->new_spi), esp_tuple->spi);

            err = 0;
            goto out_err;
        }

        n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator))
            / sizeof(struct hip_locator_info_addr_item);
        HIP_DEBUG(" %d locator addresses\n", n);

        locator_addr = (const struct hip_locator_info_addr_item *)
                       (locator + 1);
        print_esp_tuple(esp_tuple);

        while (n > 0) {
            esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
                                                          &locator_addr->address,
                                                          &seq->update_id);
            n--;

            if (n > 0) {
                locator_addr++;
            }
        }

        HIP_DEBUG("locator addr: new tuple ");
        print_esp_tuple(esp_tuple);
    }

out_err:
    return err;
}

/**
 * Process an UPDATE packet. When announcing new spis/addresses, the other
 * end may still keep sending data with old spis and addresses. Therefore,
 * old values are valid until an ack is received.
 *
 * @todo: SPI parameters did not work earlier and could not be used for creating
 * connection state for updates - check if the situation is still the same
 *
 * @param common the UPDATE packet
 * @param tuple the connection tracking tuple corresponding to the UPDATE packet
 * @param ctx packet context
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_update(const struct hip_common *common,
                         struct tuple *tuple,
                         const struct hip_fw_context *ctx)
{
    const struct hip_seq      *seq             = NULL;
    const struct hip_esp_info *esp_info        = NULL;
    const struct hip_ack      *ack             = NULL;
    const struct hip_locator  *locator         = NULL;
    const struct hip_spi      *spi             = NULL;
    struct tuple              *other_dir_tuple = NULL;
    const struct in6_addr     *ip6_src         = &ctx->src;
    int                        err             = 1;

    /* get params from UPDATE message */
    seq      = hip_get_param(common, HIP_PARAM_SEQ);
    esp_info = hip_get_param(common, HIP_PARAM_ESP_INFO);
    ack      = hip_get_param(common, HIP_PARAM_ACK);
    locator  = hip_get_param(common, HIP_PARAM_LOCATOR);
    spi      = hip_get_param(common, HIP_PARAM_ESP_INFO);

    /* connection changed to a path going through this firewall */
    if (tuple == NULL) {
        // @todo this should only be the case, if (old_spi == 0) != new_spi -> check

        /* attempt to create state for new connection */
        if (esp_info && locator && seq) {
            struct hip_data  *data           = NULL;
            struct slist     *other_dir_esps = NULL;
            struct esp_tuple *esp_tuple      = NULL;

            HIP_DEBUG("setting up a new connection...\n");

            data = get_hip_data(common);

            /* TODO also process anchor here
             *
             * active_anchor is set, next_anchor might be NULL
             */

            /** FIXME the firewall should not care about locator for esp tracking
             *
             * NOTE: modify this regardingly! */
            if (!insert_connection_from_update(data, esp_info, locator, seq)) {
                /* insertion failed */
                HIP_DEBUG("connection insertion failed\n");

                free(data);
                err = 0;
                goto out_err;
            }

            /* insertion successful -> go on */
            tuple = get_tuple_by_hits(&common->hits, &common->hitr);


            if (tuple->direction == ORIGINAL_DIR) {
                other_dir_tuple = &tuple->connection->reply;
                other_dir_esps  = tuple->connection->reply.esp_tuples;
            } else {
                other_dir_tuple = &tuple->connection->original;
                other_dir_esps  = tuple->connection->original.esp_tuples;
            }

            /* we have to consider the src ip address in case of cascading NATs (see above FIXME) */
            esp_tuple = esp_tuple_from_esp_info(esp_info, ip6_src, other_dir_tuple);

            other_dir_tuple->esp_tuples = append_to_slist(other_dir_esps,
                                                          esp_tuple);
            insert_esp_tuple(esp_tuple);

            HIP_DEBUG("connection insertion successful\n");

            free(data);
        } else {
            /* unknown connection, but insufficient parameters to set up state */
            HIP_DEBUG("insufficient parameters to create new connection with UPDATE\n");

            err = 0;
            goto out_err;
        }
    } else {
        /* we already know this connection */
        struct slist     *other_dir_esps = NULL;
        struct esp_tuple *esp_tuple      = NULL;

        if (tuple->direction == ORIGINAL_DIR) {
            other_dir_tuple = &tuple->connection->reply;
            other_dir_esps  = tuple->connection->reply.esp_tuples;
        } else {
            other_dir_tuple = &tuple->connection->original;
            other_dir_esps  = tuple->connection->original.esp_tuples;
        }

        /* distinguishing different UPDATE types and type combinations
         *
         * TODO check processing of parameter combinations
         */
        if (esp_info && locator && seq) {
            /* Handling single esp_info and locator parameters
             * Readdress with mobile-initiated rekey */
            esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));

            if (!esp_tuple) {
                err = 0;
                goto out_err;
            }

            if (!update_esp_tuple(esp_info, locator, seq, esp_tuple)) {
                err = 0;
                goto out_err;
            }
        } else if (locator && seq) {
            /* Readdress without rekeying */
            esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->new_spi));

            if (esp_tuple == NULL) {
                err = 0;
                goto out_err;
                /* if mobile host spi not intercepted, but valid */
            }

            if (!update_esp_tuple(NULL, locator, seq, esp_tuple)) {
                err = 0;
                goto out_err;
            }
        } else if (esp_info && seq) {
            /* replying to Readdress with mobile-initiated rekey */
            if (ntohl(esp_info->old_spi) != ntohl(esp_info->new_spi)) {
                esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));

                if (esp_tuple == NULL) {
                    if (tuple->connection->state != STATE_ESTABLISHING_FROM_UPDATE) {
                        err = 0;
                        goto out_err;
                    } else {                   /* connection state is being established from update */
                        struct esp_tuple *new_esp = esp_tuple_from_esp_info(esp_info,
                                                                            ip6_src,
                                                                            other_dir_tuple);

                        other_dir_tuple->esp_tuples = append_to_slist(other_dir_esps,
                                                                      new_esp);
                        insert_esp_tuple(new_esp);
                        tuple->connection->state = STATE_ESTABLISHED;
                    }
                } else if (!update_esp_tuple(esp_info, NULL, seq, esp_tuple)) {
                    err = 0;
                    goto out_err;
                }
            } else {
                esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));

                /* only add new tuple, if we don't already have it */
                if (esp_tuple == NULL) {
                    struct esp_tuple *new_esp = esp_tuple_from_esp_info(esp_info,
                                                                        ip6_src, other_dir_tuple);

                    other_dir_tuple->esp_tuples = append_to_slist(other_dir_esps,
                                                                  new_esp);
                    insert_esp_tuple(new_esp);
                }
            }
        }
    }

    /* everything should be set now in order to process eventual anchor params */
    HIP_IFEL(esp_prot_conntrack_update(common, tuple), 0,
             "failed to process anchor parameter\n");

out_err:
    return err;
}

/**
 * Process a CLOSE packet
 *
 * @param common the CLOSE packet
 * @param tuple the connection tracking tuple corresponding to the CLOSE packet
 * @param ctx packet context
 * @param ip6_src the source address
 * @param ip6_dst the destination address
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_close(UNUSED const struct in6_addr *ip6_src,
                        UNUSED const struct in6_addr *ip6_dst,
                        UNUSED const struct hip_common *common,
                        struct tuple *tuple,
                        UNUSED const struct hip_fw_context *ctx)
{
    int err = 1;

    HIP_DEBUG("\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
    HIP_IFEL(!tuple, 0, "tuple is NULL\n");

    tuple->state = STATE_CLOSING;

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE\n");
    hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE);
    hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
    return err;
}

/**
 * Process CLOSE_ACK and remove the connection.
 *
 * @param common the CLOSE_ACK packet
 * @param tuple the connection tracking tuple corresponding to the CLOSE_ACK packet
 * @param ctx packet context
 * @param ip6_src the source address
 * @param ip6_dst the destination address
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_close_ack(UNUSED const struct in6_addr *ip6_src,
                            UNUSED const struct in6_addr *ip6_dst,
                            UNUSED const struct hip_common *common,
                            struct tuple *tuple,
                            UNUSED const struct hip_fw_context *ctx)
{
    int err = 1;

    // set timeout UAL + 2MSL ++ (?)
    HIP_DEBUG("\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE_ACK\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
    HIP_IFEL(!tuple, 0, "tuple is NULL\n");

    tuple->state = STATE_CLOSING;
    remove_connection(tuple->connection);
out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE_ACK\n");
    hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
    hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
    return err;     //notify details not specified
}

/**
 * Process a HIP packet using the connection tracking procedures and issue
 * a verdict.
 *
 * @param ip6_src source address of the packet
 * @param ip6_dst destination address of the packet
 * @param common the packet to be processed
 * @param tuple the tuple or NULL if a new connection
 * @param verify_responder currently unused
 * @param accept_mobile process UPDATE packets
 * @param ctx context for the packet
 *
 * @return 1 if packet if passed the verifications or otherwise 0
 */
static int check_packet(const struct in6_addr *ip6_src,
                        const struct in6_addr *ip6_dst,
                        struct hip_common *common,
                        struct tuple *tuple,
                        const int verify_responder,
                        const int accept_mobile,
                        struct hip_fw_context *ctx)
{
#ifdef CONFIG_HIP_OPPORTUNISTIC
    hip_hit_t       phit;
    struct in6_addr all_zero_addr;
#endif
    struct in6_addr hit;
    int             err = 1;

    HIP_DEBUG("check packet: type %d \n", common->type_hdr);

    // new connection can only be started with I1 of from update packets
    // when accept_mobile is true
    if (!(tuple || common->type_hdr == HIP_I1 ||
          (common->type_hdr == HIP_UPDATE && accept_mobile))) {
        HIP_DEBUG("hip packet type %d cannot start a new connection\n",
                  common->type_hdr);

        err = 0;
        goto out_err;
    }

    // verify sender signature when required and available
    // no signature in I1 and handle_r1 does verification
    if (tuple && common->type_hdr != HIP_I1 && common->type_hdr != HIP_R1
        && common->type_hdr != HIP_LUPDATE
        && tuple->hip_tuple->data->src_hi != NULL) {
        // verify HI -> HIT mapping
        HIP_DEBUG("verifying hi -> hit mapping...\n");

        /* we have to calculate the hash ourselves to check the
         * hi -> hit mapping */
        hip_host_id_to_hit(tuple->hip_tuple->data->src_hi, &hit,
                           HIP_HIT_TYPE_HASH100);

        // match received hit and calculated hit
        if (ipv6_addr_cmp(&hit, &tuple->hip_tuple->data->src_hit)) {
            HIP_INFO("HI -> HIT mapping does NOT match\n");

            err = 0;
            goto out_err;
        }
        HIP_INFO("HI -> HIT mapping verified\n");

        HIP_DEBUG("verifying signature...\n");
        if (tuple->hip_tuple->data->verify(tuple->hip_tuple->data->src_pub_key,
                                           common)) {
            HIP_INFO("Signature verification failed\n");

            err = 0;
            goto out_err;
        }

        HIP_INFO("Signature successfully verified\n");

        HIP_DEBUG_HIT("src hit", &tuple->hip_tuple->data->src_hit);
        HIP_DEBUG_HIT("dst hit", &tuple->hip_tuple->data->dst_hit);
    }

    // handle different packet types now
    if (common->type_hdr == HIP_I1) {
        if (tuple == NULL) {
            // create a new tuple
            struct hip_data *data = get_hip_data(common);

#ifdef CONFIG_HIP_OPPORTUNISTIC
            //if peer hit is all-zero in I1 packet, replace it with pseudo hit
            memset(&all_zero_addr, 0, sizeof(struct in6_addr));

            if (IN6_ARE_ADDR_EQUAL(&common->hitr, &all_zero_addr)) {
                hip_opportunistic_ipv6_to_hit(ip6_dst, &phit,
                                              HIP_HIT_TYPE_HASH100);
                data->dst_hit = (struct in6_addr) phit;
            }
#endif

            insert_new_connection(data);

            // TODO call free for all pointer members of data - comment by Rene
            free(data);
        } else {
            HIP_DEBUG("I1 for existing connection\n");

            // TODO shouldn't we drop this?
            err = 1;
            goto out_err;
        }
    } else if (common->type_hdr == HIP_R1) {
        err = handle_r1(common, tuple, verify_responder, ctx);
    } else if (common->type_hdr == HIP_I2) {
        err = handle_i2(common, tuple, ctx);
    } else if (common->type_hdr == HIP_R2) {
        err = handle_r2(common, tuple, ctx);
    } else if (common->type_hdr == HIP_UPDATE) {
        if (!(tuple && tuple->hip_tuple->data->src_hi != NULL)) {
            HIP_DEBUG("signature was NOT verified\n");
        }

        if (tuple == NULL) {
            // new connection
            if (!accept_mobile) {
                err = 0;
            } else if (verify_responder) {
                err = 0;                 // as responder hi not available
            }
        }

        if (err) {
            err = handle_update(common, tuple, ctx);
        }
    } else if (common->type_hdr == HIP_NOTIFY) {
        // don't process and let pass through
        err = 1;
    } else if (common->type_hdr == HIP_CLOSE) {
        err = handle_close(ip6_src, ip6_dst, common, tuple, ctx);
    } else if (common->type_hdr == HIP_CLOSE_ACK) {
        err   = handle_close_ack(ip6_src, ip6_dst, common, tuple, ctx);
        tuple = NULL;
    } else if (common->type_hdr == HIP_LUPDATE) {
        err = esp_prot_conntrack_lupdate(common, tuple, ctx);
    } else {
        HIP_ERROR("unknown packet type\n");
        err = 0;
    }

    if (err && tuple) {
        // update time_stamp only on valid packets
        // for new connections time_stamp is set when creating
        if (tuple->connection) {
            gettimeofday(&tuple->connection->time_stamp, NULL);
        } else {
            HIP_DEBUG("Tuple connection NULL, could not timestamp\n");
        }
    }

    HIP_DEBUG("udp_encap_hdr=%p tuple=%p err=%d\n", ctx->udp_encap_hdr, tuple, err);

    /* Cache UDP port numbers (at the moment, used only by the ESP relay) */
    if (ctx->udp_encap_hdr && (err == 1) && tuple) {
        tuple->src_port = ntohs(ctx->udp_encap_hdr->source);
        tuple->dst_port = ntohs(ctx->udp_encap_hdr->dest);
        HIP_DEBUG("UDP src port %d\n", tuple->src_port);
        HIP_DEBUG("UDP dst port %d\n", tuple->dst_port);
    }

out_err:
    return err;
}

/**
 * ESP relay. Requires the HIP relay service on the same host.
 *
 * @todo Currently works only with UDP encapsulated IPv4 packets.
 *
 * @param ctx context for the packet
 * @return Zero means that a new relay packet was reinjected successfully
 *         and the original should be dropped.  -1 means that the reinjected
 *         packet was processed again and should be just accepted without
 *         ESP filtering. 1 means that the packet was not related to relayin
 *         and should just proceed to ESP filtering.
 */
int hipfw_relay_esp(const struct hip_fw_context *ctx)
{
    struct iphdr   *iph   = (struct iphdr *) ctx->ipq_packet->payload;
    struct udphdr  *udph  = (struct udphdr *) ((uint8_t *) iph + iph->ihl * 4);
    int             len   = ctx->ipq_packet->data_len - iph->ihl * 4;
    struct slist   *list  = (struct slist *) esp_list;
    struct tuple   *tuple = NULL;
    struct hip_esp *esp   = ctx->transport_hdr.esp;
    int             err   = 0;
    uint32_t        spi;

    HIP_IFEL(!list, -1, "List is empty\n");
    HIP_IFEL(iph->protocol != IPPROTO_UDP, -1,
             "Protocol is not UDP. Not relaying packet.\n\n");
    HIP_IFEL(!esp, -1, "No ESP header\n");

    spi = ntohl(esp->esp_spi);
    HIP_IFEL(!(tuple = get_tuple_by_esp(NULL, spi)), 0,
             "No tuple, skip\n");

    HIP_DEBUG("SPI is 0x%lx\n", spi);

    HIP_IFEL(tuple->esp_relay == 0, -1, "Relay is off for this tuple\n");

    HIP_IFEL(ipv6_addr_cmp(&ctx->dst, &tuple->esp_relay_daddr) == 0, 1,
             "Reinjected relayed packet, passing it\n");

    HIP_IFEL(hip_fw_hit_is_our(&tuple->connection->original.hip_tuple->data->dst_hit),
             0, "Destination HIT belongs to us, no relaying\n");

    HIP_DEBUG_IN6ADDR("I", &tuple->connection->original.hip_tuple->data->src_hit);
    HIP_DEBUG_IN6ADDR("I", tuple->connection->original.src_ip);
    HIP_DEBUG_IN6ADDR("R", &tuple->connection->original.hip_tuple->data->dst_hit);
    HIP_DEBUG_IN6ADDR("R", tuple->connection->original.dst_ip);

    HIP_DEBUG("%d %d %d %d %d %d %d %d %d %d\n",
              tuple->src_port,
              tuple->dst_port,
              tuple->connection->original.src_port,
              tuple->connection->original.dst_port,
              tuple->connection->reply.src_port,
              tuple->connection->reply.dst_port,
              ntohs(udph->source),
              ntohs(udph->dest),
              tuple->direction,
              tuple->esp_relay_dport);

    HIP_DEBUG_IN6ADDR("src", tuple->src_ip);
    HIP_DEBUG_IN6ADDR("dst", tuple->dst_ip);
    HIP_DEBUG_IN6ADDR("esp_relay_addr", &tuple->esp_relay_daddr);

    udph->source = htons(HIP_NAT_UDP_PORT);
    udph->dest   = htons(tuple->esp_relay_dport);
    udph->check  = 0;

    HIP_DEBUG("Relaying packet\n");

    err = hip_firewall_send_outgoing_pkt(&ctx->dst,
                                         &tuple->esp_relay_daddr,
                                         (uint8_t *) iph + iph->ihl * 4, len,
                                         iph->protocol);

out_err:

    return -err;
}

/**
 * Filters esp packet. The entire rule structure is passed as an argument
 * and the HIT options are also filtered here with information from the
 * connection.
 *
 * @param ctx context for the packet
 * @return verdict for the packet (zero means drop, one means pass)
 */
int filter_esp_state(const struct hip_fw_context *ctx)
{
    const struct in6_addr *dst_addr  = NULL;
    const struct in6_addr *src_addr  = NULL;
    struct hip_esp        *esp       = NULL;
    struct tuple          *tuple     = NULL;
    struct esp_tuple      *esp_tuple = NULL;
    // don't accept packet with this rule by default
    int      err = 0;
    uint32_t spi;

    dst_addr = &ctx->dst;
    src_addr = &ctx->src;
    esp      = ctx->transport_hdr.esp;

    // needed to de-multiplex ESP traffic
    spi = ntohl(esp->esp_spi);

    // match packet against known connections
    HIP_DEBUG("filtering ESP packet against known connections...\n");

    tuple = get_tuple_by_esp(dst_addr, spi);
    //ESP packet cannot start a connection
    if (!tuple) {
        HIP_DEBUG("dst addr %s spi 0x%lx no connection found\n",
                  addr_to_numeric(dst_addr), spi);

        err = 0;
        goto out_err;
    } else {
        HIP_DEBUG("dst addr %s spi 0x%lx connection found\n",
                  addr_to_numeric(dst_addr), spi);

        err = 1;
    }

#ifdef CONFIG_HIP_MIDAUTH
    if (use_midauth && tuple->connection->pisa_state == PISA_STATE_DISALLOW) {
        HIP_DEBUG("PISA: ESP unauthorized -> dropped\n");
        err = 0;
    }
#endif

    HIP_IFEL(!(esp_tuple = find_esp_tuple(tuple->esp_tuples, spi)), -1,
             "could NOT find corresponding esp_tuple\n");

    // validate hashes of ESP packets if extension is in use
    HIP_IFEL(esp_prot_conntrack_verify(ctx, esp_tuple), -1,
             "failed to verify esp hash\n");

    // track ESP SEQ number, if hash token passed verification
    if (ntohl(esp->esp_seq) > esp_tuple->seq_no) {
        esp_tuple->seq_no = ntohl(esp->esp_seq);
    }

out_err:
    // if we are going to accept the packet, update time stamp of the connection
    if (err > 0) {
        gettimeofday(&tuple->connection->time_stamp, NULL);
    }

    HIP_DEBUG("verdict %d \n", err);

    return err;
}

/**
 * Filter connection tracking state (in general)
 *
 * @param ip6_src       source IP address of the control packet
 * @param ip6_dst       destination IP address of the packet
 * @param buf           the control packet
 * @param option        special state options to be checked
 * @param must_accept   force accepting of the packet if set to one
 * @param ctx context   for the control packet
 * @return              verdict for the packet (zero means drop, one means pass,
 *                      negative error)
 */
int filter_state(const struct in6_addr *ip6_src, const struct in6_addr *ip6_dst,
                 struct hip_common *buf, const struct state_option *option,
                 const int must_accept, struct hip_fw_context *ctx)
{
    struct hip_data *data  = NULL;
    struct tuple    *tuple = NULL;
    // FIXME results in unsafe use in filter_hip()
    int return_value = -1;      //invalid value

    // get data form the buffer and put it in a new data structure
    data = get_hip_data(buf);
    // look up the tuple in the database
    tuple = get_tuple_by_hip(data, buf->type_hdr, ip6_src);
    free(data);

    // cases where packet does not match
    if (!tuple) {
        if ((option->int_opt.value == CONN_NEW && !option->int_opt.boolean) ||
            (option->int_opt.value == CONN_ESTABLISHED && option->int_opt.boolean)) {
            return_value = 0;
            goto out_err;
        }
    } else {
        if ((option->int_opt.value == CONN_ESTABLISHED && !option->int_opt.boolean) ||
            (option->int_opt.value == CONN_NEW && option->int_opt.boolean)) {
            return_value = 0;
            goto out_err;
        }
    }

    // cases where packet matches, but will be dropped
    // do not create connection or delete existing connection
    // TODO is 'return_value = 1' correct here?
    if (!tuple) {
        HIP_DEBUG("filter_state: no tuple found \n");

        if (option->int_opt.value == CONN_NEW && option->int_opt.boolean && !must_accept) {
            return_value = 1;
            goto out_err;
        } else if (option->int_opt.value == CONN_ESTABLISHED &&
                   !option->int_opt.boolean && !must_accept) {
            return_value = 1;
            goto out_err;
        }
    } else {
        if ((option->int_opt.value == CONN_ESTABLISHED && option->int_opt.boolean
             && !must_accept) || (option->int_opt.value == CONN_NEW &&
                                  !option->int_opt.boolean && !must_accept)) {
            remove_connection(tuple->connection);
            tuple->connection = NULL;

            return_value = 1;
            goto out_err;
        }
    }

    return_value = check_packet(ip6_src, ip6_dst, buf, tuple, option->verify_responder,
                                option->accept_mobile, ctx);

out_err:
    return return_value;
}

/**
 * Packet is accepted by filtering rules but has not been
 * filtered through any state rules. Find the the tuples for the packet
 * and pass on for more filtering.
 *
 * @param ip6_src source IP address of the control packet
 * @param ip6_dst destination IP address of the control packet
 * @param buf the control packet
 * @param ctx context for the control packet
 */
int conntrack(const struct in6_addr *ip6_src,
              const struct in6_addr *ip6_dst,
              struct hip_common *buf,
              struct hip_fw_context *ctx)
{
    struct hip_data *data    = NULL;
    struct tuple    *tuple   = NULL;
    int              verdict = 0;

    // convert to new data type
    data = get_hip_data(buf);
    // look up tuple in the db
    tuple = get_tuple_by_hip(data, buf->type_hdr, ip6_src);

    // the accept_mobile parameter is true as packets
    // are not filtered here
    verdict = check_packet(ip6_src, ip6_dst, buf, tuple, 0, 1, ctx);

    free(data);

    return verdict;
}

/**
 * Fetches the wanted hip_tuple from the connection table.
 *
 * @param src_hit source HIT of the tuple
 * @param dst_hit destination HIT of the tuple
 *
 * @return the tuple matching to the given HITs or NULL if not found
 */
struct tuple *get_tuple_by_hits(const struct in6_addr *src_hit, const struct in6_addr *dst_hit)
{
    struct dlist *list = hip_list;

    while (list) {
        struct hip_tuple *tuple = list->data;
        if (IN6_ARE_ADDR_EQUAL(src_hit, &tuple->data->src_hit) &&
            IN6_ARE_ADDR_EQUAL(dst_hit, &tuple->data->dst_hit)) {
            HIP_DEBUG("connection found, \n");
            //print_data(data);
            return tuple->tuple;
        }
        list = list->next;
    }
    HIP_DEBUG("get_tuple_by_hits: no connection found\n");
    return NULL;
}
