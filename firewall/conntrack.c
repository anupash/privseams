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
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <sys/time.h>
#include <linux/netfilter_ipv4.h>

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
#include "hslist.h"
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


static struct dlist *hip_list  = NULL;
static struct dlist *esp_list  = NULL;
static struct slist *conn_list = NULL;

/**
 * Interval between sweeps in hip_fw_conntrack_periodic_cleanup(),
 * in seconds.
 * Because all active connections are traversed, this should not be too
 * low for performance reasons.
 *
 * @see hip_fw_conntrack_periodic_cleanup()
 */
time_t cleanup_interval = 60; // 1 minute

/**
 * Connection timeout in seconds, or zero to disable timeout.
 * This actually specifies the minimum period of inactivity before a
 * connection is considered stale. Thus, a connection may be inactive for
 * at most ::connection_timeout plus ::cleanup_interval seconds before
 * getting removed.
 *
 * @see hip_fw_conntrack_periodic_cleanup()
 */
time_t connection_timeout = 60 * 5; // 5 minutes

enum {
    STATE_NEW,
    STATE_ESTABLISHED,
    STATE_ESTABLISHING_FROM_UPDATE,
    STATE_CLOSING
};

/**
 * Number of currently managed iptables rules for ESP speedup (-u option).
 * @see hip_fw_manage_esp_rule();
 */
static unsigned int total_esp_rules_count = 0;

/*------------print functions-------------*/
/**
 * prints out the list of addresses of esp_addr_list
 *
 * @param addresses list of addresses
 *
 */
static void print_esp_addresses(const struct hip_ll *const addresses)
{
    const struct hip_ll_node *node = addresses->head;

    HIP_DEBUG("ESP dst addr list:\n");
    while (node) {
        const struct esp_address *const addr = node->ptr;
        HIP_DEBUG_IN6ADDR("dst address: ", &addr->dst_addr);
        if (addr && addr->update_id != NULL) {
            HIP_DEBUG("update id: %d\n", *addr->update_id);
        }
        node = node->next;
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
    HIP_DEBUG("esp_tuple: spi:0x%lx new_spi:0x%lx spi_update_id: %u tuple dir:%d\n",
              esp_tuple->spi, esp_tuple->new_spi, esp_tuple->spi_update_id,
              esp_tuple->tuple->direction);

    print_esp_addresses(&esp_tuple->dst_addresses);
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
}

/** Fetch a hip_tuple from the connection table.
 *
 * @param data packet information constructed from the packet
 * @param type_hdr HIP control packet type (HIP_I1 etc)
 * @param ip6_from the source address of the control packet
 * @return the tuple or NULL, if not found.
 */
static struct tuple *get_tuple_by_hip(const struct hip_data *data,
                                      const uint8_t type_hdr,
                                      const struct in6_addr *ip6_from)
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

    /* In the case the entry was not found, place the real peer HIT in
     * the entries if the HIT happened to be an opportunistic one */
    if (type_hdr == HIP_R1) {
        update_peer_opp_info(data, ip6_from);
        return get_tuple_by_hip(data, -1, ip6_from);
    }

    HIP_DEBUG("get_tuple_by_hip: no connection found\n");
    return NULL;
}

/**
 * Find an entry from the given list that matches to the given address
 *
 * @param addresses the list to be searched for
 * @param addr the address to matched from the list
 * @return the entry from the list that matched to the given address, or NULL if not found
 */
static struct esp_address *get_esp_address(const struct hip_ll *const addresses,
                                           const struct in6_addr *const addr)
{
    const struct hip_ll_node *node = addresses->head;

    HIP_DEBUG_IN6ADDR("Looking for entry with addr: ", addr);

    while (node) {
        const struct esp_address *const esp_addr = node->ptr;
        HIP_DEBUG_IN6ADDR("dst addr: ", &esp_addr->dst_addr);

        if (IN6_ARE_ADDR_EQUAL(&esp_addr->dst_addr, addr)) {
            HIP_DEBUG("matching entry found\n");
            /* cannot return esp_addr because
             * a) it is const but this function's return type is not
             * b) it is const for good reason: we do not intend to modify it
             * c) casting esp_addr to 'struct esp_address*' causes a compiler
             *    error.
             */
            return node->ptr;
        }
        node = node->next;
    }
    HIP_DEBUG("no matching entry found\n");
    return NULL;
}

/**
 * Set up or remove iptables rules to bypass userspace processing of the
 * SPI/destination pairs as specified by @a esp_tuple and @a dest.
 * This can greatly improve firewall throughput.
 *
 * @param esp_tuple Determines the SPI.
 * @param dest      The corresponding destination address to bypass. May be
 *                  a IPv6-mapped IPv4 address.
 * @param insert    Insert new rule if true, remove existing if false.
 * @return          0 if rules were modified, -1 otherwise.
 *
 * @note This feature may be turned off completely by the -u command line option.
 *       It is also automatically deactivated for connections that demand
 *       more advanced connection tracking.
 *       In these cases, -1 is returned even though there was not even an
 *       attempt to modify rules.
 *
 * @note This interferes, in one way or another, with userspace_ipsec,
 *       relay, LSI, midauth, lightweight-update and esp_prot. Care was
 *       taken to not break these features though.
 *
 * @see update_esp_address()
 * @see free_esp_tuple()
 * @see ::esp_speedup
 */
static int hip_fw_manage_esp_rule(const struct esp_tuple *const esp_tuple,
                                  const struct in6_addr *const dest,
                                  const bool insert)
{
    int         err   = 0;
    const char *flag  = insert ? "-I" : "-D";
    const char *table = NULL;

    if (!esp_speedup || hip_userspace_ipsec) {
        return -1;
    }

    HIP_ASSERT(esp_tuple);
    HIP_ASSERT(dest);

    if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED) {
        HIP_DEBUG("ESP Transforms requested; not handled via iptables "
                  "since we need to inspect packets\n");
        return -1;
    }

    if (esp_tuple->tuple->esp_relay) {
        HIP_DEBUG("ESP Relay requested; not handled via iptables "
                  "since we need packet rewriting\n");
        return -1;
    }

    switch (esp_tuple->tuple->hook) {
    case NF_IP_LOCAL_IN:
        table = "HIPFW-INPUT";
        break;
    case NF_IP_FORWARD:
        table = "HIPFW-FORWARD";
        break;
    case NF_IP_LOCAL_OUT:
        table = "HIPFW-OUTPUT";
        break;
    default:
        HIP_ERROR("Packet was received via unsupported netfilter hook %d\n",
                  esp_tuple->tuple->hook);
        return -1;
    }

    HIP_DEBUG("insert         = %d\n", insert);
    HIP_DEBUG("table          = %s\n", table);
    HIP_DEBUG("esp_tuple->spi = 0x%08X\n", esp_tuple->spi);
    HIP_DEBUG_IN6ADDR("dest ip", dest);

    if (IN6_IS_ADDR_V4MAPPED(dest)) {
        char           daddr[INET_ADDRSTRLEN];
        struct in_addr dest4;

        IPV6_TO_IPV4_MAP(dest, &dest4);
        HIP_IFEL(!inet_ntop(AF_INET, &dest4, daddr, sizeof(daddr)), -1,
                 "inet_ntop: %s\n", strerror(errno));

        if (esp_tuple->tuple->connection->udp_encap) {
            /* SPI is the first 32bit value in encapsulating UDP payload, so
             * we may use a simple u32 Pattern. Here, '4&0x1FFF=0' ensures
             * we're not processing a fragmented packet.
             */
            err = system_printf("iptables %s %s -p UDP "
                                "--dport 10500 --sport 10500 -d %s -m u32 "
                                "--u32 '4&0x1FFF=0 && 0>>22&0x3C@8=0x%08X' -j ACCEPT",
                                flag, table, daddr, esp_tuple->spi);
        } else {
            err = system_printf("iptables %s %s -p 50 "
                                "-d %s -m esp --espspi 0x%08X -j ACCEPT",
                                flag, table, daddr, esp_tuple->spi);
        }
    } else {
        char daddr[INET6_ADDRSTRLEN];
        HIP_IFEL(!inet_ntop(AF_INET6, dest, daddr, sizeof(daddr)), -1,
                 "inet_ntop: %s\n", strerror(errno));

        HIP_ASSERT(!esp_tuple->tuple->connection->udp_encap);
        err = system_printf("ip6tables %s %s -p 50 "
                            "-d %s -m esp --espspi 0x%08X -j ACCEPT",
                            flag, table, daddr, esp_tuple->spi);
    }

    if (err == EXIT_SUCCESS) {
        total_esp_rules_count += (insert ? 1 : -1);
        HIP_DEBUG("total_esp_rules_count = %d\n", total_esp_rules_count);
    }

out_err:
    return err == EXIT_SUCCESS ? 0 : -1;
}

/**
 * Set up or remove iptables rules to bypass userspace processing of all
 * SPI/destination pairs associated with @a esp_tuple.
 *
 * @param esp_tuple Determines the SPI and all destination addresses.
 * @param insert    Insert rules if true, remove existing if false.
 *
 * @see hip_fw_manage_esp_rule()
 */
static void hip_fw_manage_esp_tuple(const struct esp_tuple *const esp_tuple,
                                    const bool insert)
{
    const struct hip_ll_node *node = esp_tuple->dst_addresses.head;
    while (node) {
        hip_fw_manage_esp_rule(esp_tuple, node->ptr, insert);
        node = node->next;
    }
}

/**
 * Set up or remove iptables rules to bypass userspace processing of all
 * ESP SPI/destination pairs associated with @a tuple.
 *
 * @param tuple  Determines all SPI/destination pairs.
 * @param insert Insert rules if true, remove existing if false.
 *
 * @see hip_fw_manage_esp_rule()
 * @see hip_fw_manage_esp_tuple()
 */
void hip_fw_manage_all_esp_tuples(const struct tuple *const tuple,
                                  const bool insert)
{
    const struct slist *lst = tuple->esp_tuples;
    while (lst) {
        hip_fw_manage_esp_tuple(lst->data, insert);
        lst = lst->next;
    }
}

/**
 * Insert or update a destination address associated with an ESP tuple.
 * If the address is already known, its update_id is replaced with the new
 * value.
 *
 * @param esp_tuple The esp tuple to update the destination address of.
 * @param addr      The address to be added or updated.
 * @param upd_id    The update id. May be NULL if the address is inserted for
 *                  the first time.
 *
 * @return  0 on success
 *         -1 on error (if insufficient memory is available for a new
 *                      esp address object)
 */
static int update_esp_address(struct esp_tuple *const esp_tuple,
                              const struct in6_addr *const addr,
                              const uint32_t *const upd_id)
{
    bool                 remove_esp_addr = false;
    int                  err             = 0;
    struct hip_ll *const addresses       = &esp_tuple->dst_addresses;
    struct esp_address  *esp_addr        = get_esp_address(addresses, addr);
    HIP_DEBUG("address: %s \n", addr_to_numeric(addr));

    // if necessary, allocate a new esp_address object
    if (!esp_addr) {
        HIP_IFEL(!(esp_addr = malloc(sizeof(*esp_addr))), -1,
                 "Allocating esp_address object failed");
        remove_esp_addr     = true;
        esp_addr->dst_addr  = *addr;
        esp_addr->update_id = NULL; // gets set below
        HIP_IFEL(hip_ll_add_first(addresses, esp_addr) != 0, -1,
                 "Inserting ESP address object into list of destination addresses failed");
    }

    // update the update ID
    if (upd_id) {
        if (!esp_addr->update_id) {
            HIP_IFEL(!(esp_addr->update_id = malloc(sizeof(*esp_addr->update_id))),
                     -1, "Allocating update ID object failed");
        }
        *esp_addr->update_id = *upd_id;
    }

    hip_fw_manage_esp_rule(esp_tuple, addr, true);
    return err;

out_err:
    if (esp_addr && remove_esp_addr) {
        if (hip_ll_get(addresses, 0) == esp_addr) {
            hip_ll_del_first(addresses, NULL);
        }
        free(esp_addr);
    }
    return err;
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
            if (dst_addr && get_esp_address(&tuple->dst_addresses, dst_addr) != NULL) {
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
 * Initialize and store a new HIP/ESP connnection into the connection
 * table.
 *
 * @param data The connection-related data to be inserted.
 * @param ctx  The packet context. Note that source and destination HITs
 *             are always taken from @a data rather than @a ctx.
 * @return 0 on success, -1 otherwise
 *
 * @see remove_connection()
 */
static int insert_new_connection(const struct hip_data *const data,
                                 const struct hip_fw_context *const ctx)
{
    int err = 0;

    struct connection *const connection = calloc(1, sizeof(struct connection));
    HIP_IFEL(!connection, -1, "Allocating connection object failed");

    connection->state     = STATE_ESTABLISHED;
    connection->udp_encap = ctx->udp_encap_hdr ? true : false;
    connection->timestamp = time(NULL);

    //original direction tuple
    connection->original.state      = HIP_STATE_UNASSOCIATED;
    connection->original.direction  = ORIGINAL_DIR;
    connection->original.esp_tuples = NULL;
    connection->original.connection = connection;
    connection->original.hip_tuple  = malloc(sizeof(struct hip_tuple));
    HIP_IFEL(!connection->original.hip_tuple, -1,
             "Allocating hip_tuple object failed");
    connection->original.hip_tuple->tuple = &connection->original;
    connection->original.hip_tuple->data  = malloc(sizeof(struct hip_data));
    HIP_IFEL(!connection->original.hip_tuple->data, -1,
             "Allocating hip_data object failed");
    connection->original.hip_tuple->data->src_hit = data->src_hit;
    connection->original.hip_tuple->data->dst_hit = data->dst_hit;
    connection->original.hip_tuple->data->src_hi  = NULL;
    connection->original.hip_tuple->data->verify  = NULL;

    //reply direction tuple
    connection->reply.state      = HIP_STATE_UNASSOCIATED;
    connection->reply.direction  = REPLY_DIR;
    connection->reply.esp_tuples = NULL;
    connection->reply.connection = connection;
    connection->reply.hip_tuple  = malloc(sizeof(struct hip_tuple));
    HIP_IFEL(!connection->reply.hip_tuple, -1,
             "Allocating hip_tuple object failed");
    connection->reply.hip_tuple->tuple = &connection->reply;
    connection->reply.hip_tuple->data  = malloc(sizeof(struct hip_data));
    HIP_IFEL(!connection->reply.hip_tuple->data, -1,
             "Allocating hip_data object failed");
    connection->reply.hip_tuple->data->src_hit = data->dst_hit;
    connection->reply.hip_tuple->data->dst_hit = data->src_hit;
    connection->reply.hip_tuple->data->src_hi  = NULL;
    connection->reply.hip_tuple->data->verify  = NULL;

    //add tuples to list
    hip_list  = append_to_list(hip_list, connection->original.hip_tuple);
    hip_list  = append_to_list(hip_list, connection->reply.hip_tuple);
    conn_list = append_to_slist(conn_list, connection);

out_err:
    return err;
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
                case HIP_HI_ECDSA:
                    EC_KEY_free(hip_tuple->data->src_pub_key);
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
        struct esp_address *addr = NULL;

        // remove eventual cached anchor elements for this esp tuple
        esp_prot_conntrack_remove_state(esp_tuple);

        // remove all associated addresses
        while ((addr = hip_ll_del_first(&esp_tuple->dst_addresses, NULL))) {
            hip_fw_manage_esp_rule(esp_tuple, &addr->dst_addr, false);
            free(addr->update_id);
            free(addr);
        }

        esp_tuple->tuple = NULL;
        free(esp_tuple);
    }
}

/**
 * deallocate dynamically allocated parts of the esp_tuples list
 *
 * @param tuple the tuple containing the esp_tuples to be freed
 */
static void remove_esp_tuples(struct tuple *const tuple)
{
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
}

/**
 * deallocate dynamically allocated parts of a tuple along with its associated HIP and ESP tuples
 *
 * @param tuple the tuple to be freed
 */
static void remove_tuple(struct tuple *const tuple)
{
    if (tuple) {
        // remove hip_tuple from helper list
        hip_list = remove_link_dlist(hip_list,
                                     find_in_dlist(hip_list, tuple->hip_tuple));
        // now free hip_tuple and its members
        free_hip_tuple(tuple->hip_tuple);
        tuple->hip_tuple = NULL;

        remove_esp_tuples(tuple);
        tuple->connection = NULL;
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
    struct slist *conn_link;

    HIP_DEBUG("tuple list before: \n");
    print_tuple_list();

    HIP_DEBUG("esp list before: \n");
    print_esp_list();

    if (connection) {
        HIP_ASSERT(conn_link = find_in_slist(conn_list, connection));
        conn_list = remove_link_slist(conn_list, conn_link);
        free(conn_link);

        remove_tuple(&connection->original);
        remove_tuple(&connection->reply);

        free(connection);
    }

    HIP_DEBUG("tuple list after: \n");
    print_tuple_list();

    HIP_DEBUG("esp list after: \n");
    print_esp_list();
}

/**
 * Create an esp_tuple object from an esp_info message parameter and with a
 * specific destination address.
 *
 * @param esp_info a pointer to an ESP info parameter in the control message
 * @param ctx context of the packet to be tracked
 * @param tuple a pointer to a tuple structure
 * @return zero on success, -1 otherwise
 */
static int esp_tuple_from_esp_info(const struct hip_esp_info *const esp_info,
                                   const struct hip_fw_context *const ctx,
                                   struct tuple *const tuple)
{
    HIP_ASSERT(ctx);
    HIP_ASSERT(tuple);

    if (!esp_info) {
        HIP_ERROR("ESP_INFO parameter missing, cannot derive ESP state\n");
        return -1;
    }

    struct esp_tuple *const esp_tuple = calloc(1, sizeof(struct esp_tuple));
    if (esp_tuple) {
        struct tuple *other_dir = NULL;
        if (tuple->direction == ORIGINAL_DIR) {
            other_dir = &tuple->connection->reply;
        } else {
            other_dir = &tuple->connection->original;
        }

        esp_tuple->spi   = ntohl(esp_info->new_spi);
        esp_tuple->tuple = other_dir;
        hip_ll_init(&esp_tuple->dst_addresses);
        if (update_esp_address(esp_tuple, &ctx->src, NULL)) {
            HIP_ERROR("adding or updating ESP destination address failed");
            return -1;
        }
        other_dir->esp_tuples = append_to_slist(other_dir->esp_tuples,
                                                esp_tuple);
        esp_list = append_to_list(esp_list, esp_tuple);

        return 0;
    }

    HIP_ERROR("Allocating esp_tuple object failed");
    free(esp_tuple);

    return -1;
}

/**
 * Initialize and insert connection based on the given parameters from UPDATE
 * packet.
 *
 * @param common UPDATE packet for which new connection should be inserted
 * @param esp_info a pointer to an ESP info message parameter.
 * @param locator a pointer to a locator message parameter.
 * @param seq a pointer to a sequence number of an UPDATE message.
 *
 * @return  0 on success
 *         -1 on error
 */
static int insert_connection_from_update(const struct hip_common *const common,
                                         const struct hip_fw_context *const ctx,
                                         const struct hip_esp_info *const esp_info)
{
    struct hip_data *data  = get_hip_data(common);
    struct tuple    *tuple = NULL;

    if (insert_new_connection(data, ctx)) {
        HIP_ERROR("connection insertion failed\n");
        return -1;
    }

    tuple = get_tuple_by_hits(&common->hits, &common->hitr);

    if (!tuple || esp_tuple_from_esp_info(esp_info, ctx, tuple)) {
        HIP_ERROR("unable to create esp state from UPDATE packet\n");
        return -1;
    }

    return 0;
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

    if (esp_relay && ctx->udp_encap_hdr) {
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
        HIP_DEBUG("tuple dir=%d, sport=%d, dport=%d, rel=%d\n", tuple->direction,
                  tuple->src_port, tuple->dst_port, tuple->esp_relay);

        HIP_DEBUG("reverse tuple src=%d dst=%d\n", reverse_tuple->src_port,
                  reverse_tuple->dst_port);
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
    }

out_err:
    return err;
}

/** verify message authenticity for message types with existing security state
 *
 * @param common    the hip packet to be verified
 * @param tuple     the corresponding connection tuple
 * @return 1 for valid packets, 0 otherwise
 */
static int hip_fw_verify_packet(struct hip_common *const common,
                                const struct tuple *const tuple)
{
    HIP_ASSERT(common != NULL);
    HIP_ASSERT(tuple != NULL);
    HIP_ASSERT(tuple->hip_tuple != NULL);
    HIP_ASSERT(tuple->hip_tuple->data != NULL);
    HIP_ASSERT(tuple->hip_tuple->data->src_hi != NULL);

    /* no need to verify that HI matches HIT in this packet, as:
     * 1.) HI -> HIT matching must be ensured when saving HI in this tuple
     * 2.) tuple is looked up corresponding to HITs */

    HIP_DEBUG("verifying signature...\n");
    if (tuple->hip_tuple->data->verify(tuple->hip_tuple->data->src_pub_key,
                                       common)) {
        HIP_INFO("Signature verification failed\n");

        return 0;
    }

    HIP_INFO("Signature successfully verified\n");

    return 1;
}

/** verify message authenticity for message types without existing security
 *  state and store credentials for valid packets
 *
 * @param common    the hip packet to be verified
 * @param tuple     the corresponding connection tuple
 * @return 1 for valid packets, 0 otherwise
 */
static int hip_fw_verify_and_store_host_id(struct hip_common *const common,
                                           struct tuple *const tuple)
{
    const struct hip_host_id *const host_id = hip_get_param(common, HIP_PARAM_HOST_ID);
    struct in6_addr                 hit;
    hip_tlv_len                     len = 0;
    int                             err = 0;

    HIP_IFEL(!host_id, -1, "Awaiting HOST_ID in control message, but none found\n");

    len = hip_get_param_total_len(host_id);

    /* we have to calculate the hash ourselves to check the
     * hi -> hit mapping */
    hip_host_id_to_hit(host_id, &hit, HIP_HIT_TYPE_HASH100);

    // match received hit and calculated hit
    HIP_IFEL(ipv6_addr_cmp(&hit, &common->hits), 1,
             "HI -> HIT mapping does NOT match\n");
    HIP_INFO("HI -> HIT mapping verified\n");

    // init hi parameter and copy
    HIP_IFEL(!(tuple->hip_tuple->data->src_hi = malloc(len)),
             -ENOMEM, "Out of memory\n");
    memcpy(tuple->hip_tuple->data->src_hi, host_id, len);

    switch (hip_get_host_id_algo(tuple->hip_tuple->data->src_hi)) {
    case HIP_HI_RSA:
        tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_rsa((const struct hip_host_id_priv *) host_id, 0);
        tuple->hip_tuple->data->verify      = hip_rsa_verify;
        break;
    case HIP_HI_ECDSA:
        tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_ecdsa((const struct hip_host_id_priv *) host_id, 0);
        tuple->hip_tuple->data->verify      = hip_ecdsa_verify;
        break;
    case HIP_HI_DSA:
        tuple->hip_tuple->data->src_pub_key = hip_key_rr_to_dsa((const struct hip_host_id_priv *) host_id, 0);
        tuple->hip_tuple->data->verify      = hip_dsa_verify;
        break;
    default:
        HIP_ERROR("Could not store public key, because host id algorithm is unknown.\n");
        err = -1;
        goto out_err;
    }

    err = !hip_fw_verify_packet(common, tuple);

out_err:
    if (err) {
        // free keys depending on cipher
        if (tuple->hip_tuple->data->src_hi) {
            switch (hip_get_host_id_algo(tuple->hip_tuple->data->src_hi)) {
            case HIP_HI_RSA:
                RSA_free(tuple->hip_tuple->data->src_pub_key);
                break;
            case HIP_HI_DSA:
                DSA_free(tuple->hip_tuple->data->src_pub_key);
                break;
            default:
                HIP_ERROR("Could not free public key, because key type is unknown.\n");
            }
        }

        tuple->hip_tuple->data->src_pub_key = NULL;
        tuple->hip_tuple->data->verify      = NULL;

        free(tuple->hip_tuple->data->src_hi);
        tuple->hip_tuple->data->src_hi = NULL;
    }

    return err;
}

/**
 * Process an I1 packet. This function sets up a new connection for the HIT
 * tuple conveyed in the packet's HIP header.
 *
 * @param common the R1 packet
 * @param tuple the corresponding connection tuple
 * @param ctx the context
 *
 * @return always 1
 */
static int handle_i1(const struct hip_common *const common,
                     struct tuple *const tuple,
                     const struct hip_fw_context *const ctx)
{
    if (tuple) {
        HIP_DEBUG("I1 for existing connection, "
                  "re-establishing connection state\n");

        remove_connection(tuple->connection);
    }

    // create a new tuple
    const struct in6_addr all_zero_addr = { { { 0 } } };
    hip_hit_t             phit;
    struct hip_data      *data = get_hip_data(common);

    //if peer hit is all-zero in I1 packet, replace it with pseudo hit
    if (IN6_ARE_ADDR_EQUAL(&common->hitr, &all_zero_addr)) {
        hip_opportunistic_ipv6_to_hit(&ctx->dst, &phit,
                                      HIP_HIT_TYPE_HASH100);
        data->dst_hit = (struct in6_addr) phit;
    }

    insert_new_connection(data, ctx);

    return 1;
}

/**
 * Process an R1 packet. This function also stores the HI of the Responder
 * to be able to verify signatures also later. The HI is stored only if the
 * signature in R1 was valid.
 *
 * @param common the R1 packet
 * @param tuple the corresponding connection tuple
 * @param ctx the context
 *
 * @return one if the packet was ok or zero otherwise
 */
static int handle_r1(struct hip_common *const common,
                     struct tuple *const tuple,
                     struct hip_fw_context *const ctx)
{
    if (hip_fw_verify_and_store_host_id(common, tuple)) {
        HIP_ERROR("unable to create security state from R1 packet\n");
        return 0;
    }

    // check if the R1 contains ESP protection transforms
    if (esp_prot_conntrack_R1_tfms(common, tuple)) {
        HIP_ERROR("failed to track esp protection extension transforms\n");
        return 0;
    }

    if (!hipfw_midauth_add_challenge(ctx, tuple->midauth_nonce)) {
        HIP_ERROR("failed to add midauth challenge\n");
        return 0;
    }

    return 1;
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
static int handle_i2(struct hip_common *const common,
                     struct tuple *const tuple,
                     struct hip_fw_context *const ctx)
{
    struct tuple                    *other_dir = NULL;
    const struct hip_esp_info *const esp_info  = hip_get_param(common, HIP_PARAM_ESP_INFO);

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir = &tuple->connection->reply;
    } else {
        other_dir = &tuple->connection->original;
    }

    if (!hipfw_midauth_verify_challenge(ctx, other_dir->midauth_nonce)) {
        HIP_ERROR("failed to verify midauth challenge\n");
        return 0;
    }

    if (hip_fw_verify_and_store_host_id(common, tuple)) {
        HIP_ERROR("unable to create security state from I2 packet\n");
        return 0;
    }

    if (esp_tuple_from_esp_info(esp_info, ctx, tuple)) {
        HIP_ERROR("unable to create esp state from I2 packet\n");
        return 0;
    }

    /* check if the I2 contains ESP protection anchor and store state */
    if (esp_prot_conntrack_I2_anchor(common, tuple)) {
        HIP_ERROR("failed to track esp protection extension state\n");
        return 0;
    }

    if (!hipfw_midauth_add_challenge(ctx, tuple->midauth_nonce)) {
        HIP_ERROR("failed to add midauth challenge\n");
        return 0;
    }

    return 1;
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
static int handle_r2(struct hip_common *const common,
                     struct tuple *const tuple,
                     const struct hip_fw_context *const ctx)
{
    const struct tuple              *other_dir = NULL;
    const struct hip_esp_info *const esp_info  = hip_get_param(common, HIP_PARAM_ESP_INFO);

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir = &tuple->connection->reply;
    } else {
        other_dir = &tuple->connection->original;
    }

    if (!hipfw_midauth_verify_challenge(ctx, other_dir->midauth_nonce)) {
        HIP_ERROR("failed to verify midauth challenge\n");
        return 0;
    }

    if (!hip_fw_verify_packet(common, tuple)) {
        HIP_ERROR("failed to verify R2 packet\n");
        return 0;
    }

    if (esp_tuple_from_esp_info(esp_info, ctx, tuple)) {
        HIP_ERROR("unable to create esp state from I2 packet\n");
        return 0;
    }

    /* check if the R2 contains ESP protection anchor and store state */
    if (esp_prot_conntrack_R2_anchor(common, tuple)) {
        HIP_ERROR("failed to track esp protection extension state\n");
        return 0;
    }

    if (hipfw_handle_relay_to_r2(common, ctx)) {
        HIP_ERROR("handling of relay_to failed\n");
        return 0;
    }

    return 1;
}

/**
 * Update an existing ESP tuple according to the given parameters Argument
 * esp_info or locator may be NULL. SPI or ip_addr will not be updated in that case.
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

    if (esp_info && locator && seq) {
        HIP_DEBUG("esp_info, locator and seq\n");

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
            HIP_IFEL(update_esp_address(esp_tuple,
                                        &locator_addr->address,
                                        &seq->update_id) == -1, 0,
                     "adding or updating ESP destination address failed");
            n--;

            if (n > 0) {
                locator_addr++;
            }
        }
    } else if (esp_info && seq) {
        HIP_DEBUG("esp_info and seq\n");

        if (ntohl(esp_info->old_spi) != esp_tuple->spi) {
            HIP_DEBUG("update_esp_tuple: esp_info spi no match esp_info:0x%lx tuple:0x%lx\n",
                      ntohl(esp_info->old_spi), esp_tuple->spi);

            err = 0;
            goto out_err;
        }

        esp_tuple->new_spi       = ntohl(esp_info->new_spi);
        esp_tuple->spi_update_id = seq->update_id;
    } else if (locator && seq) {
        HIP_DEBUG("locator and seq\n");

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
            HIP_IFEL(!update_esp_address(esp_tuple,
                                         &locator_addr->address,
                                         &seq->update_id), 0,
                     "adding or updating ESP destination address failed");
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
 * Process the first UPDATE packet. This function sets up a new connection if
 * no state for the association already exists.
 *
 * @param common the UPDATE packet
 * @param tuple the corresponding connection tuple
 * @param esp_info ESP_INFO parameter contained in the UPDATE packet
 * @param locator LOCATOR parameter contained in the UPDATE packet
 * @param seq SEQ parameter contained in the UPDATE packet
 *
 * @return zero if the packet was ok, negative value otherwise
 */
static int handle_first_update(const struct hip_common *const common,
                               const struct hip_fw_context *const ctx,
                               const struct tuple *const tuple,
                               const struct hip_esp_info *const esp_info,
                               const struct hip_locator *const locator,
                               const struct hip_seq *const seq)
{
    /* connection changed to a path passing through this firewall */
    if (!tuple) {
        HIP_DEBUG("setting up a new connection...\n");

        /** FIXME the firewall should not care about locator for esp tracking
         *
         * NOTE: modify this regardingly! */
        if (insert_connection_from_update(common, ctx, esp_info)) {
            HIP_ERROR("connection insertion failed\n");

            return -1;
        }
    } else {
        const struct tuple *other_dir = NULL;
        struct esp_tuple   *esp_tuple = NULL;

        if (tuple->direction == ORIGINAL_DIR) {
            other_dir = &tuple->connection->reply;
        } else {
            other_dir = &tuple->connection->original;
        }

        if (!(esp_tuple = find_esp_tuple(other_dir->esp_tuples,
                                         ntohl(esp_info->old_spi)))) {
            HIP_DEBUG("existing ESP state does not include current SPI, "
                      "re-establishing connection state\n");

            remove_connection(tuple->connection);

            /** FIXME the firewall should not care about locator for esp tracking
             *
             * NOTE: modify this regardingly! */
            if (insert_connection_from_update(common, ctx, esp_info)) {
                HIP_ERROR("connection insertion failed\n");

                return -1;
            }

            return 0;
        }

        if (!update_esp_tuple(esp_info, locator, seq, esp_tuple)) {
            HIP_ERROR("failed to update ESP state\n");
            return -1;
        }
    }

    return 0;
}

/**
 * Process the second UPDATE packet. This function sets up ESP state if
 * no state for the association already exists.
 *
 * @param tuple the corresponding connection tuple
 * @param ctx context of the UPDATE packet
 * @param esp_info ESP_INFO parameter contained in the UPDATE packet
 * @param seq SEQ parameter contained in the UPDATE packet
 *
 * @return zero if the packet was ok, negative value otherwise
 */
static int handle_second_update(struct tuple *const tuple,
                                const struct hip_fw_context *const ctx,
                                const struct hip_esp_info *const esp_info,
                                const struct hip_seq *const seq)
{
    struct tuple     *other_dir = NULL;
    struct esp_tuple *esp_tuple = NULL;

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir = &tuple->connection->reply;
    } else {
        other_dir = &tuple->connection->original;
    }

    if (!(esp_tuple = find_esp_tuple(other_dir->esp_tuples,
                                     ntohl(esp_info->old_spi)))) {
        // init and add new esp_tuple
        if (esp_tuple_from_esp_info(esp_info, ctx, tuple)) {
            HIP_ERROR("failed to set up ESP state\n");
            return -1;
        }
    } else {
        if (!update_esp_tuple(esp_info, NULL, seq, esp_tuple)) {
            HIP_ERROR("failed to update ESP state\n");
            return -1;
        }
    }

    return 0;
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
static int handle_update(struct hip_common *const common,
                         struct tuple **tuple,
                         struct hip_fw_context *const ctx)
{
    const struct hip_esp_info *esp_info  = NULL;
    const struct hip_locator  *locator   = NULL;
    const struct hip_seq      *seq       = NULL;
    const struct hip_ack      *ack       = NULL;
    struct tuple              *other_dir = NULL;
    int                        err       = 1;

    /* classify UPDATE message */
    esp_info = hip_get_param(common, HIP_PARAM_ESP_INFO);
    locator  = hip_get_param(common, HIP_PARAM_LOCATOR);
    seq      = hip_get_param(common, HIP_PARAM_SEQ);
    ack      = hip_get_param(common, HIP_PARAM_ACK);

    if (esp_info && locator && seq) {
        if (handle_first_update(common, ctx, *tuple, esp_info, locator, seq)) {
            HIP_ERROR("unable to process first UPDATE message\n");
            return 0;
        }

        /* if there was no tuple before, the previous packet processing will have
         * created it */
        if (!(*tuple)) {
            *tuple = get_tuple_by_hits(&common->hits, &common->hitr);
        }

        if (!(*tuple) || !hipfw_midauth_add_challenge(ctx, (*tuple)->midauth_nonce)) {
            HIP_ERROR("failed to add midauth challenge\n");
            return 0;
        }
    } else if (esp_info && seq && ack) {
        if (*tuple && (*tuple)->direction == ORIGINAL_DIR) {
            other_dir = &(*tuple)->connection->reply;
        } else if (*tuple) {
            other_dir = &(*tuple)->connection->original;
        } else {
            HIP_ERROR("Insufficient stored state to process UPDATE\n");
            return 0;
        }

        if (!hipfw_midauth_verify_challenge(ctx, other_dir->midauth_nonce)) {
            HIP_ERROR("failed to verify midauth challenge\n");
            return 0;
        }

        if (!hip_fw_verify_packet(common, *tuple)) {
            HIP_ERROR("failed to verify UPDATE packet\n");
            return 0;
        }

        if (handle_second_update(*tuple, ctx, esp_info, seq)) {
            HIP_ERROR("unable to process second UPDATE message\n");
            return 0;
        }

        if (!hipfw_midauth_add_challenge(ctx, (*tuple)->midauth_nonce)) {
            HIP_ERROR("failed to add midauth challenge\n");
            return 0;
        }
    } else if (ack) {
        if (*tuple && (*tuple)->direction == ORIGINAL_DIR) {
            other_dir = &(*tuple)->connection->reply;
        } else if (*tuple) {
            other_dir = &(*tuple)->connection->original;
        } else {
            HIP_ERROR("Insufficient stored state to process UPDATE\n");
            return 0;
        }

        if (!hipfw_midauth_verify_challenge(ctx, other_dir->midauth_nonce)) {
            HIP_ERROR("failed to verify midauth challenge\n");
            return 0;
        }

        if (!hip_fw_verify_packet(common, *tuple)) {
            HIP_ERROR("failed to verify UPDATE packet\n");
            return 0;
        }
    } else {
        HIP_DEBUG("Unknown parameter combination in UPDATE\n");
        return 0;
    }

    /* everything should be set now in order to process eventual anchor params */
    HIP_IFEL(esp_prot_conntrack_update(common, *tuple), 0,
             "failed to process anchor parameter\n");

out_err:
    return err;
}

/**
 * Process a CLOSE packet
 *
 * @param common the CLOSE packet
 * @param tuple the connection tracking tuple corresponding to the CLOSE packet
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_close(struct hip_common *const common,
                        struct tuple *const tuple)
{
    int err = 1;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
    HIP_IFEL(!tuple, 1, "no connection state for CLOSE\n");

    HIP_IFEL(!hip_fw_verify_packet(common, tuple), 0,
             "failed to verify CLOSE packet\n");

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
 *
 * @return one if packet was processed successfully or zero otherwise
 */
static int handle_close_ack(struct hip_common *const common,
                            struct tuple *const tuple)
{
    int err = 1;

    // set timeout UAL + 2MSL ++ (?)
    HIP_DEBUG("\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_CLOSE_ACK\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
    HIP_IFEL(!tuple, 1, "no connection state for CLOSE_ACK\n");

    HIP_IFEL(!hip_fw_verify_packet(common, tuple), 0,
             "failed to verify CLOSE_ACK packet\n");

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
 * @param common the packet to be processed
 * @param tuple the tuple or NULL if a new connection
 * @param ctx context for the packet
 *
 * @return 1 if packet if passed the verifications or otherwise 0
 */
static int check_packet(struct hip_common *common,
                        struct tuple *tuple,
                        struct hip_fw_context *ctx)
{
    int err = 1;

    HIP_DEBUG("check packet: type %d \n", common->type_hdr);

    // new connection can only be started with I1 of from update packets
    if (!(tuple || common->type_hdr == HIP_I1 || common->type_hdr == HIP_UPDATE)) {
        HIP_DEBUG("hip packet type %d cannot start a new connection\n",
                  common->type_hdr);

        err = 0;
        goto out_err;
    }

    // handle different packet types now
    if (common->type_hdr == HIP_I1) {
        err = handle_i1(common, tuple, ctx);
    } else if (common->type_hdr == HIP_R1) {
        err = handle_r1(common, tuple, ctx);
    } else if (common->type_hdr == HIP_I2) {
        err = handle_i2(common, tuple, ctx);
    } else if (common->type_hdr == HIP_R2) {
        err = handle_r2(common, tuple, ctx);
    } else if (common->type_hdr == HIP_UPDATE) {
        err = handle_update(common, &tuple, ctx);
    } else if (common->type_hdr == HIP_NOTIFY) {
        err = 1;
    } else if (common->type_hdr == HIP_CLOSE) {
        err = handle_close(common, tuple);
    } else if (common->type_hdr == HIP_CLOSE_ACK) {
        err = handle_close_ack(common, tuple);
        goto out_err;
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
            tuple->connection->timestamp = time(NULL);
        } else {
            HIP_DEBUG("Tuple connection NULL, could not timestamp\n");
        }

        tuple->hook = ctx->ipq_packet->hook;
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

    HIP_IFEL(!list, -1, "ESP List is empty\n");
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
    HIP_DEBUG_IN6ADDR("R", &tuple->connection->original.hip_tuple->data->dst_hit);

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
    struct hip_esp        *esp       = NULL;
    struct tuple          *tuple     = NULL;
    struct esp_tuple      *esp_tuple = NULL;
    // don't accept packet with this rule by default
    int      err = 0;
    uint32_t spi;

    dst_addr = &ctx->dst;
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
        tuple->connection->timestamp = time(NULL);
    }

    HIP_DEBUG("verdict %d \n", err);

    return err;
}

/**
 * Filter connection tracking state (in general)
 *
 * @param buf           the control packet
 * @param option        special state options to be checked
 * @param must_accept   force accepting of the packet if set to one
 * @param ctx context   for the control packet
 * @return              verdict for the packet (zero means drop, one means pass,
 *                      negative error)
 */
int filter_state(struct hip_common *buf, const struct state_option *option,
                 const int must_accept, struct hip_fw_context *ctx)
{
    struct hip_data *data  = NULL;
    struct tuple    *tuple = NULL;
    // FIXME results in unsafe use in filter_hip()
    int return_value = -1;      //invalid value

    // get data form the buffer and put it in a new data structure
    data = get_hip_data(buf);
    // look up the tuple in the database
    tuple = get_tuple_by_hip(data, buf->type_hdr, &ctx->src);
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

    return_value = check_packet(buf, tuple, ctx);

out_err:
    return return_value;
}

/**
 * Packet is accepted by filtering rules but has not been
 * filtered through any state rules. Find the the tuples for the packet
 * and pass on for more filtering.
 *
 * @param buf the control packet
 * @param ctx context for the control packet
 */
int conntrack(struct hip_common *buf,
              struct hip_fw_context *ctx)
{
    struct hip_data *data    = NULL;
    struct tuple    *tuple   = NULL;
    int              verdict = 0;

    // convert to new data type
    data = get_hip_data(buf);
    // look up tuple in the db
    tuple = get_tuple_by_hip(data, buf->type_hdr, &ctx->src);

    // the accept_mobile parameter is true as packets
    // are not filtered here
    verdict = check_packet(buf, tuple, ctx);

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

/**
 * Parse one line of `iptables -nvL` formatted output and extract packet count,
 * SPI and destination IP if the line corresponds to a previously set up ESP
 * rule.
 * This takes into account specifically the kinds of rules that can be created
 * by hip_fw_manage_esp_rule().
 *
 * @param input        The line to be parsed.
 * @param packet_count Out: receives the packet count.
 * @param spi          Out: receives the SPI, unless the packet count was zero.
 * @param dest         Out: receives the destination IP, unless the packet count
 *                          was zero.
 * @return             true if @a input could be parsed as an ESP
 *                     rule (and at least @a packet_count was set), false
 *                     otherwise.
 *
 * @note Short-circuiting behaviour for @a spi and @a dest (see description).
 *
 * @see detect_esp_rule_activity()
 * @see hip_fw_manage_esp_rule()
 */
static bool parse_iptables_esp_rule(const char *const input,
                                    unsigned int *const packet_count,
                                    uint32_t *const spi,
                                    struct in6_addr *const dest)
{
    static const char u32_prefix[] = "u32 0x4&0x1fff=0x0&&0x0>>0x16&0x3c@0x8=0x";

    /*
     * In iptables output, one column is optional. So we try the long
     * format first and fall back to the shorter one (see sscanf call
     * below).
     * The %45s format is used here because 45 is the maximum IPv6 address
     * length, considering all variations (i.e. INET6_ADDRSTRLEN - 1).
     */
    static const char *formats[] = { "%u %*u %*s %*s %*2[!f-] %*s %*s %*s %45s",
                                     "%u %*u %*s %*s %*s %*s %*s %45s" };

    char        ip[INET6_ADDRSTRLEN];
    const char *str_spi;

    // there's two ways of specifying SPIs in a rule
    // (see hip_fw_manage_esp_rule)

    if ((str_spi = strstr(input, "spi:"))) {
        // non-UDP
        if (sscanf(str_spi, "spi:%u", spi) < 1) {
            HIP_ERROR("Unexpected iptables output (spi): '%s'\n", input);
            return false;
        }
    } else if ((str_spi = strstr(input, u32_prefix))) {
        // UDP
        // spi follows u32_prefix string as a hex number
        // (always host byte order)
        if (sscanf(&str_spi[sizeof(u32_prefix) - 1], "%x", spi) < 1) {
            HIP_ERROR("Unexpected iptables output (u32 match): '%s'\n", input);
            return false;
        }
    } else {
        // no SPI specified, so it's no ESP rule
        return false;
    }

    // grab packet count and destination IP.
    if (sscanf(input, formats[0], packet_count, ip) < 2) {
        // retry with alternative format before we give up
        if (sscanf(input, formats[1], packet_count, ip) < 2) {
            HIP_ERROR("Unexpected iptables output (number of colums): '%s'\n", input);
            return false;
        }
    }

    // IP not needed, unless there was activity
    if (*packet_count > 0) {
        char *slash;

        // IP may be in /128 format, strip the suffix
        if ((slash = strchr(ip, '/'))) {
            *slash = '\0';
        }

        // parse destination IP; try IPv6 first, then IPv4
        if (!inet_pton(AF_INET6, ip, dest)) {
            struct in_addr addr4;
            if (!inet_pton(AF_INET, ip, &addr4)) {
                HIP_ERROR("Unexpected iptables output: '%s'\n", input);
                HIP_ERROR("Can't parse destination IP: %s\n", ip);
                return false;
            }

            IPV4_TO_IPV6_MAP(&addr4, dest);
        }
    }

    return true;
}

/**
 * Update timestamps of all ESP tuples where corresponding iptables rules'
 * packet counters are non-zero.
 * Currently, this works by parsing the output of iptables and ip6tables
 * to extract and zero the packet counters.
 *
 * @param now We consider this the current time.
 * @return    Number of rules that were identified with an esp tuple
 *            (not necessarily the number of tuples updated), or -1 if
 *            communication with iptables failed.
 *
 * @note Ugly approach, yes. You may be tempted to statically link in
 *       libiptc, and I'd generally approve of it because while it was never
 *       meant to be used publicly, quite some projects have relied on it
 *       without burning their fingers too badly for a long time now.  On the
 *       other hand, libiptc would blow up iptables communication code at most
 *       other places, and the output format is unlikely to change.
 *       Furthermore, a successor to iptables (namely: nftables) with an actual
 *       API is under consideration by the netfilter team.
 */
static int detect_esp_rule_activity(const time_t now)
{
    static const char *const bins[]   = { "iptables", "ip6tables" };
    static const char *const chains[] = { "HIPFW-INPUT", "HIPFW-OUTPUT",
                                          "HIPFW-FORWARD" };

    unsigned int chain, bin, ret = 0;

    for (bin = 0; bin < ARRAY_SIZE(bins); ++bin) {
        for (chain = 0; chain < ARRAY_SIZE(chains); ++chain) {
            char  bfr[256];
            FILE *p;

            snprintf(bfr, sizeof(bfr), "%s -nvL -Z %s", bins[bin], chains[chain]);
            if (!(p = popen(bfr, "r"))) {
                HIP_ERROR("popen(\"%s\"): %s\n", bfr, strerror(errno));
                return -1;
            }

            while (fgets(bfr, sizeof(bfr), p)) {
                unsigned int    packet_count;
                uint32_t        spi;
                struct in6_addr dest;

                if (parse_iptables_esp_rule(bfr, &packet_count, &spi, &dest)) {
                    ret += 1;
                    if (packet_count > 0) {
                        struct tuple *const tuple = get_tuple_by_esp(&dest, spi);
                        if (!tuple) {
                            HIP_ERROR("Stray ESP rule: SPI = %u\n", spi);
                            continue;
                        }

                        tuple->connection->timestamp = now;
                        HIP_DEBUG("Activity detected: SPI = %u\n", spi);
                        HIP_DEBUG_IN6ADDR("dest: ", &dest);
                    }
                }
            }

            if (!feof(p)) {
                HIP_ERROR("fgets(), bin: %s, chain %s: %s\n",
                          bins[bin], chains[chain], strerror(errno));
                return -1;
            }

            pclose(p);
        }
    }

    HIP_DEBUG("-> %u\n", ret);
    return ret;
}

/**
 * Do some necessary bookkeeping concerning connection tracking.
 * Currently, this only makes sure that stale locations will be removed.
 * The actual tasks will be run at most once per ::connection_timeout
 * seconds, no matter how often you call the function.
 *
 * @note Don't call this from a thread or timer, since most of hipfw is not
 *       reentrant (and so this function isn't either).
 */
void hip_fw_conntrack_periodic_cleanup(void)
{
    static time_t      last_check = 0; // timestamp of last call
    struct slist      *iter_conn;
    struct connection *conn;

    if (connection_timeout == 0 || !filter_traffic) {
        // timeout disabled, or no connections
        // tracked in the first place
        return;
    }

    const time_t now = time(NULL);

    if (now < last_check) {
        last_check = now;
        HIP_ERROR("System clock skew detected; internal timestamp reset\n");
    }

    if (now - last_check >= cleanup_interval) {
        HIP_DEBUG("Checking for connection timeouts\n");

        // If connections are covered by iptables rules, we rely on kernel
        // packet counters to update timestamps indirectly for these.

        if (total_esp_rules_count > 0) {
            // cast to signed value
            const int found = detect_esp_rule_activity(now);
            if (found == -1 || (unsigned int) found != total_esp_rules_count) {
                HIP_ERROR("Not all ESP tuples' packet counts were found\n");
            }
        }

        iter_conn = conn_list;
        while (iter_conn) {
            conn      = iter_conn->data;
            iter_conn = iter_conn->next; // iter_conn might get removed

            if (now < conn->timestamp) {
                conn->timestamp = now;
                HIP_ERROR("Packet timestamp skew detected; timestamp reset\n");
            }

            if (now - conn->timestamp >= connection_timeout) {
                HIP_DEBUG("Connection timed out:\n");
                HIP_DEBUG_HIT("src HIT", &conn->original.hip_tuple->data->src_hit);
                HIP_DEBUG_HIT("dst HIT", &conn->original.hip_tuple->data->dst_hit);

                remove_connection(conn);
            }
        }

        last_check = now;
    }
}
