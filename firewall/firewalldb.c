/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @todo THIS DATABASE IS REDUDANT WITH CACHE.C AND CONTAINS ONLY A SUBSET OF IT. REWRITE AND TEST!!!
 * @note this code is linked to the use of hip_firewall_set_bex_data()
 * @todo move the raw socket initialization to somewhere else
 *
 * @brief Write a short summary
 *
 * @author <Put all existing author information here>
 * @author another Author another@author.net
 */

#define _BSD_SOURCE

#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "firewalldb.h"
#include "cache.h"
#include "firewall_defines.h"
#include "lib/core/icomm.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/builder.h"

#include "lib/tool/checksum.h"

#define DISABLE_hip_firewall_hldb_dump
#define DISABLE_firewall_init_raw_sock_esp_v6

static int firewall_raw_sock_tcp_v4        = 0;
static int firewall_raw_sock_udp_v4        = 0;
static int firewall_raw_sock_icmp_v4       = 0;
static int firewall_raw_sock_tcp_v6        = 0;
static int firewall_raw_sock_udp_v6        = 0;
static int firewall_raw_sock_icmp_v6       = 0;
static int firewall_raw_sock_icmp_outbound = 0;

static int firewall_raw_sock_esp_v4        = 0;

#ifndef DISABLE_firewall_init_raw_sock_esp_v6
static int firewall_raw_sock_esp_v6        = 0;
#endif

HIP_HASHTABLE *firewall_hit_lsi_ip_db;


#ifndef DISABLE_hip_firewall_hldb_dump
/**
 * display the contents of the database
 */
static void hip_firewall_hldb_dump(void)
{
    int i;
    firewall_hl_t *this;
    hip_list_t *item, *tmp;
    HIP_DEBUG("---------   Firewall db   ---------\n");
    HIP_LOCK_HT(&firewall_lsi_hit_db);

    list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i) {
        this = list_entry(item);
        HIP_DEBUG_HIT("hit_our", &this->hit_our);
        HIP_DEBUG_HIT("hit_peer", &this->hit_peer);
        HIP_DEBUG_LSI("lsi", &this->lsi);
        HIP_DEBUG_IN6ADDR("ip", &this->ip_peer);
        HIP_DEBUG("bex_state %d \n", this->bex_state);
    }
    HIP_UNLOCK_HT(&firewall_lsi_hit_db);
}

#endif

/**
 * Search in the database the given peer ip
 *
 * @param ip_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *hip_firewall_ip_db_match(const struct in6_addr *ip_peer)
{
#ifndef DISABLE_hip_firewall_hldb_dump
    hip_firewall_hldb_dump();
#endif
    HIP_DEBUG_IN6ADDR("peer ip", ip_peer);
    return (firewall_hl_t *) hip_ht_find(firewall_hit_lsi_ip_db,
                                         (void *) ip_peer);
}

/**
 * allocate memory for a new database entry
 *
 * @return the allocated database entry (caller responsible of freeing)
 */
static firewall_hl_t *hip_create_hl_entry(void)
{
    firewall_hl_t *entry = NULL;
    int err              = 0;
    HIP_IFEL(!(entry = malloc(sizeof(firewall_hl_t))),
             -ENOMEM, "No memory available for firewall database entry\n");
    memset(entry, 0, sizeof(*entry));
out_err:
    return entry;
}

/**
 * Add a default entry in the firewall db.
 *
 * @param ip    the only supplied field, the ip of the peer
 * @return      error if any
 */
int hip_firewall_add_default_entry(const struct in6_addr *ip)
{
    struct in6_addr all_zero_default_v6;
    struct in_addr all_zero_default_v4, in4;
    firewall_hl_t *new_entry  = NULL;
    firewall_hl_t *entry_peer = NULL;
    int err                   = 0;

    HIP_DEBUG("\n");

    HIP_ASSERT(ip != NULL);

    entry_peer = hip_firewall_ip_db_match(ip);

    if (!entry_peer) {
        HIP_DEBUG_IN6ADDR("ip ", ip);

        new_entry = hip_create_hl_entry();

        memset(&all_zero_default_v6, 0, sizeof(all_zero_default_v6));
        memset(&all_zero_default_v4, 0, sizeof(all_zero_default_v4));

        /* Check the lower bits of the address to make sure it is not
         * a zero address. Otherwise e.g. connections to multiple LSIs
         * don't work. */
        IPV6_TO_IPV4_MAP(ip, &in4);
        if (in4.s_addr == 0) {
            HIP_DEBUG("NULL default address\n");
            return 0;
        }

        ipv6_addr_copy(&new_entry->hit_our,  &all_zero_default_v6);
        ipv6_addr_copy(&new_entry->hit_peer, &all_zero_default_v6);
        ipv4_addr_copy(&new_entry->lsi,      &all_zero_default_v4);
        ipv6_addr_copy(&new_entry->ip_peer,  ip);
        new_entry->bex_state = FIREWALL_STATE_BEX_DEFAULT;

        hip_ht_add(firewall_hit_lsi_ip_db, new_entry);
    }

    return err;
}

/**
 * Update an existing entry. The entry is found based on the peer ip.
 * If any one of the first three params is null,
 * the corresponding field in the db entry is not updated.
 * The ip field is required so as to find the entry.
 *
 * @param *hit_our  our hit, optionally null
 * @param *hit_peer peer hit, optionally null
 * @param *lsi      peer lsi, optionally null
 * @param *ip       peer ip, NOT null
 * @param state     state of entry, required
 *
 * @return  error if any
 */
int hip_firewall_update_entry(const struct in6_addr *hit_our,
                              const struct in6_addr *hit_peer,
                              const hip_lsi_t       *lsi,
                              const struct in6_addr *ip,
                              int state)
{
    int err = 0;
    firewall_hl_t *entry_update = NULL;

    HIP_DEBUG("\n");

    HIP_ASSERT(ip != NULL &&
               (state == FIREWALL_STATE_BEX_DEFAULT        ||
                state == FIREWALL_STATE_BEX_NOT_SUPPORTED  ||
                state == FIREWALL_STATE_BEX_ESTABLISHED));

    if (ip) {
        HIP_DEBUG_IN6ADDR("ip", ip);
    }

    HIP_IFEL(!(entry_update = hip_firewall_ip_db_match(ip)), -1,
             "Did not find entry\n");

    //update the fields if new value value is not NULL
    if (hit_our) {
        ipv6_addr_copy(&entry_update->hit_our, hit_our);
    }
    if (hit_peer) {
        ipv6_addr_copy(&entry_update->hit_peer, hit_peer);
    }
    if (lsi) {
        ipv4_addr_copy(&entry_update->lsi, lsi);
    }
    entry_update->bex_state = state;

out_err:
    return err;
}

/**
 * Generate the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
static unsigned long hip_firewall_hash_ip_peer(const void *ptr)
{
    struct in6_addr *ip_peer = &((firewall_hl_t *) ptr)->ip_peer;
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, ip_peer, sizeof(*ip_peer), hash);
    return *((unsigned long *) hash);
}

/**
 * Compare two IPs
 *
 * @param ptr1: pointer to ip
 * @param ptr2: pointer to ip
 *
 * @return 0 if hashes identical, otherwise 1
 */
static int hip_firewall_match_ip_peer(const void *ptr1, const void *ptr2)
{
    return hip_firewall_hash_ip_peer(ptr1) != hip_firewall_hash_ip_peer(ptr2);
}

/**
 * Initialize an ICMP raw socket
 *
 * @param the raw socket is written into this pointer
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_outbound(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err  = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                      IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failiped\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize raw IPv4 sockets for TCP
 *
 * @param firewall_raw_sock_v4 the result will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_tcp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize UDP-based raw socket
 *
 * @param firewall_raw_sock_v4 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_udp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ICMP-based raw socket
 *
 * @param firewall_raw_sock_v4 the result is written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_v4(int *firewall_raw_sock_v4)
{
    int on  = 1, err = 0;
    int off = 0;

    *firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_BROADCAST, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
    err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP,
                     IP_PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize TCPv6 raw socket
 *
 * @param firewall_raw_sock_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_tcp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize UDPv6-based raw socket
 *
 * @param firewall_raw_sock_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_udp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ICMPv6-based raw socket
 *
 * @param hip_firewall_init_raw_sock_icmp_v6 the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_icmp_v6(int *firewall_raw_sock_v6)
{
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6,
                     IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET,
                     SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}

/**
 * Initialize ESPv4-based raw socket
 *
 * @param sock the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_esp_v4(int *sock)
{
    int on = 1, off = 0, err = 0;
    *sock = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);

    HIP_IFE(setsockopt(*sock, IPPROTO_IP, IP_RECVERR, &off, sizeof(off)), -1);
    HIP_IFE(setsockopt(*sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)), -1);
    HIP_IFE(setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), -1);

out_err:
    if (err) {
        HIP_ERROR("init sock esp v4\n");
    }
    return err;
}

#ifndef DISABLE_firewall_init_raw_sock_esp_v6
/**
 * Initialize ESPv6-based raw socket
 *
 * @param sock the created raw socket will be written here
 *
 * @return zero on success, non-zero on error
 */
static int hip_firewall_init_raw_sock_esp_v6(int *sock)
{
    int on = 1, off = 0, err = 0;
    *sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ESP);

    HIP_IFE(setsockopt(*sock, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(off)), -1);
    HIP_IFE(setsockopt(*sock, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on)), -1);
    HIP_IFE(setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)), -1);

out_err:
    if (err) {
        HIP_ERROR("init sock esp v4\n");
    }
    return err;
}

#endif

/**
 * Initialize all raw sockets
 *
 */
static void hip_firewall_init_raw_sockets(void)
{
    hip_firewall_init_raw_sock_tcp_v4(&firewall_raw_sock_tcp_v4);
    hip_firewall_init_raw_sock_udp_v4(&firewall_raw_sock_udp_v4);
    hip_firewall_init_raw_sock_icmp_v4(&firewall_raw_sock_icmp_v4);
    hip_firewall_init_raw_sock_icmp_outbound(&firewall_raw_sock_icmp_outbound);
    hip_firewall_init_raw_sock_tcp_v6(&firewall_raw_sock_tcp_v6);
    hip_firewall_init_raw_sock_udp_v6(&firewall_raw_sock_udp_v6);
    hip_firewall_init_raw_sock_icmp_v6(&firewall_raw_sock_icmp_v6);
    hip_firewall_init_raw_sock_esp_v4(&firewall_raw_sock_esp_v4);
#ifndef DISABLE_firewall_init_raw_sock_esp_v6
    hip_firewall_init_raw_sock_esp_v6(&firewall_raw_sock_esp_v6);
#endif
}

/**
 * Initialize the database
 */
void hip_firewall_init_hldb(void)
{
    firewall_hit_lsi_ip_db = hip_ht_init(hip_firewall_hash_ip_peer,
                                         hip_firewall_match_ip_peer);
    hip_firewall_init_raw_sockets();
}

/**
 * Update the state of a cached HADB entry denoted by the given HITs
 *
 * @param hit_s the source HIT of the HADB cache
 * @param hit_r the destination HIT of the HADB cache
 * @param state the new state of the HADB entry
 *
 * @return zero on success and non-zero on error
 */
int hip_firewall_set_bex_state(struct in6_addr *hit_s,
                               struct in6_addr *hit_r,
                               int state)
{
    struct in6_addr ip_src, ip_dst;
    hip_lsi_t lsi_our, lsi_peer;
    int err = 0;

    HIP_IFEL(hip_firewall_cache_db_match(hit_r, hit_s, &lsi_our, &lsi_peer,
                                         &ip_src, &ip_dst, NULL),
             -1, "Failed to query LSIs\n");
    HIP_IFEL(hip_firewall_update_entry(NULL, NULL, NULL, &ip_dst, state), -1,
             "Failed to update firewall entry\n");

out_err:
    return err;
}

/**
 * remove and deallocate the hadb cache
 *
 */
void hip_firewall_delete_hldb(void)
{
    int i;
    firewall_hl_t *this = NULL;
    hip_list_t *item, *tmp;

    HIP_DEBUG("Start hldb delete\n");
    HIP_LOCK_HT(&firewall_lsi_hit_db);

    list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i)
    {
        this = (firewall_hl_t *) list_entry(item);
        hip_ht_delete(firewall_hit_lsi_ip_db, this);
        free(this);
    }
    HIP_UNLOCK_HT(&firewall_lsi_hit_db);
    HIP_DEBUG("End hldbdb delete\n");
}

/**
 * Translate and reinject an incoming packet back to the networking stack.
 * Supports TCP, UDP and ICMP. LSI code uses this to translate
 * the HITs from an incoming packet to the corresponding LSIs. Also,
 * the system-based opportunistic mode uses this to translate the HITs of
 * an incoming packet to an IPv4 or IPv6 address.
 *
 * @param src_hit source HIT of the packet
 * @param dst_hit destination HIT of the packet
 * @param msg a pointer to the transport layer header of the packet
 * @param len the length of the packet in bytes
 * @param proto the transport layer protocol of the packet
 * @param new ttl value for the transformed packet
 *
 * @todo this function could also be used by the proxy?
 *
 * @return zero on success and non-zero on error
 */
int hip_firewall_send_incoming_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto,
                                   int ttl)
{
    int err               = 0, sent, sa_size;
    int firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
    struct ip *iphdr      = NULL;
    struct udphdr *udp    = NULL;
    struct tcphdr *tcp    = NULL;
    struct icmphdr *icmp  = NULL;
    struct sockaddr_storage src, dst;
    struct sockaddr_in6 *sock_src6 = NULL, *sock_dst6 = NULL;
    struct sockaddr_in *sock_src4 = NULL, *sock_dst4 = NULL;
    struct in6_addr any   = IN6ADDR_ANY_INIT;

    HIP_ASSERT(src_hit != NULL && dst_hit != NULL);
    sock_src4 = (struct sockaddr_in *) &src;
    sock_dst4 = (struct sockaddr_in *) &dst;
    sock_src6 = (struct sockaddr_in6 *) &src;
    sock_dst6 = (struct sockaddr_in6 *) &dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    if (IN6_IS_ADDR_V4MAPPED(src_hit)) {
        sock_src4->sin_family = AF_INET;
        sock_dst4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(src_hit, &(sock_src4->sin_addr));
        IPV6_TO_IPV4_MAP(dst_hit, &(sock_dst4->sin_addr));
        sa_size               = sizeof(struct sockaddr_in);
        HIP_DEBUG_LSI("src4 addr ", &(sock_src4->sin_addr));
        HIP_DEBUG_LSI("dst4 addr ", &(sock_dst4->sin_addr));
    } else {
        sock_src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
        sock_dst6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
        sa_size                = sizeof(struct sockaddr_in6);
        is_ipv6                = 1;
    }

    switch (proto) {
    case IPPROTO_UDP:
        _HIP_DEBUG("IPPROTO_UDP\n");
        if (is_ipv6) {
            HIP_DEBUG(" IPPROTO_UDP v6\n");
            firewall_raw_sock              = firewall_raw_sock_udp_v6;
            ((struct udphdr *) msg)->check = ipv6_checksum(IPPROTO_UDP,
                                               &sock_src6->sin6_addr,
                                               &sock_dst6->sin6_addr, msg, len);
        } else {
            HIP_DEBUG(" IPPROTO_UDP v4\n");
            firewall_raw_sock = firewall_raw_sock_udp_v4;

            udp               = (struct udphdr *) msg;

            sa_size           = sizeof(struct sockaddr_in);

            udp->check        = htons(0);
            udp->check        = ipv4_checksum(IPPROTO_UDP,
                                              (uint8_t *) &(sock_src4->sin_addr),
                                              (uint8_t *) &(sock_dst4->sin_addr),
                                              (uint8_t *) udp, len);
            memmove((msg + sizeof(struct ip)), (uint8_t *) udp, len);
        }
        break;
    case IPPROTO_TCP:
        _HIP_DEBUG("IPPROTO_TCP\n");
        tcp        = (struct tcphdr *) msg;
        tcp->check = htons(0);

        if (is_ipv6) {
            HIP_DEBUG(" IPPROTO_TCP v6\n");
            firewall_raw_sock = firewall_raw_sock_tcp_v6;
            tcp->check        = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr,
                                              &sock_dst6->sin6_addr, msg, len);
        } else {
            HIP_DEBUG(" IPPROTO_TCP v4\n");
            firewall_raw_sock = firewall_raw_sock_tcp_v4;

            tcp->check        = ipv4_checksum(IPPROTO_TCP,
                                              (uint8_t *) &(sock_src4->sin_addr),
                                              (uint8_t *) &(sock_dst4->sin_addr),
                                              (uint8_t *) tcp, len);
            _HIP_DEBUG("checksum %x, len=%d\n", htons(tcp->check), len);
            _HIP_DEBUG_LSI("src", &(sock_src4->sin_addr));
            _HIP_DEBUG_LSI("dst", &(sock_dst4->sin_addr));

            memmove((char *) (msg + sizeof(struct ip)), (uint8_t *) tcp, len);
        }
        break;
    case IPPROTO_ICMP:
        firewall_raw_sock = firewall_raw_sock_icmp_v4;
        icmp              = (struct icmphdr *) msg;
        icmp->checksum    = htons(0);
        icmp->checksum    = inchksum(icmp, len);
        memmove((char *) (msg + sizeof(struct ip)), (uint8_t *) icmp, len);
        _HIP_DEBUG("icmp->type = %d\n", icmp->type);
        _HIP_DEBUG("icmp->code = %d\n", icmp->code);
        break;
    case IPPROTO_ICMPV6:
        goto not_sending;
        break;
    default:
        HIP_ERROR("No protocol family found\n");
        break;
    }

    if (!is_ipv6) {
        iphdr         = (struct ip *) msg;
        iphdr->ip_v   = 4;
        iphdr->ip_hl  = sizeof(struct ip) >> 2;
        iphdr->ip_tos = 0;
        iphdr->ip_len = len + iphdr->ip_hl * 4;
        iphdr->ip_id  = htons(0);
        iphdr->ip_off = 0;
        iphdr->ip_ttl = ttl;
        iphdr->ip_p   = proto;
        iphdr->ip_src = sock_src4->sin_addr;
        iphdr->ip_dst = sock_dst4->sin_addr;
        iphdr->ip_sum = htons(0);

        /* @todo: move the socket option to fw initialization */
        if (setsockopt(firewall_raw_sock, IPPROTO_IP,
                       IP_HDRINCL, &on, sizeof(on))) {
            HIP_IFEL(err, -1, "setsockopt IP_HDRINCL ERROR\n");
        }


        _HIP_HEXDUMP("hex", iphdr, (len + sizeof(struct ip)));
        sent = sendto(firewall_raw_sock, iphdr,
                      iphdr->ip_len, 0,
                      (struct sockaddr *) &dst, sa_size);
        if (sent != (len + sizeof(struct ip))) {
            HIP_ERROR("Could not send the all requested" \
                      " data (%d/%d)\n", sent,
                      iphdr->ip_len);
        } else {
            HIP_DEBUG("sent=%d/%d \n",
                      sent, (len + sizeof(struct ip)));
            HIP_DEBUG("Packet sent ok\n");
        }
    }    //if !is_ipv6

out_err:
    if (is_ipv6) {
        ipv6_addr_copy(&sock_src6->sin6_addr, &any);
    } else {
        sock_src4->sin_addr.s_addr = INADDR_ANY;
        sock_src4->sin_family      = AF_INET;
    }

    bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
not_sending:
    if (err) {
        HIP_DEBUG("sterror %s\n", strerror(errno));
    }
    return err;
}

/**
 * translate and reinject an incoming packet
 *
 * @param src_hit source HIT of the packet
 * @param dst_hit destination HIT of the packet
 * @param msg a pointer to the transport header of the packet
 * @param len length of the packet
 * @param proto transport layer protocol
 *
 * @return zero on success and non-zero on error
 *
 * @todo unify common code with hip_firewall_send_outgoing_pkt()
 */
int hip_firewall_send_outgoing_pkt(const struct in6_addr *src_hit,
                                   const struct in6_addr *dst_hit,
                                   uint8_t *msg, uint16_t len,
                                   int proto)
{
    int err               = 0, sent, sa_size;
    int firewall_raw_sock = 0, is_ipv6 = 0;

    struct sockaddr_storage src, dst;
    struct sockaddr_in6 *sock_src6, *sock_dst6;
    struct sockaddr_in *sock_src4, *sock_dst4;
    struct in6_addr any = IN6ADDR_ANY_INIT;

    HIP_ASSERT(src_hit != NULL && dst_hit != NULL);

    sock_src4 = (struct sockaddr_in *) &src;
    sock_dst4 = (struct sockaddr_in *) &dst;
    sock_src6 = (struct sockaddr_in6 *) &src;
    sock_dst6 = (struct sockaddr_in6 *) &dst;

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    if (IN6_IS_ADDR_V4MAPPED(src_hit)) {
        sock_src4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(src_hit, &sock_src4->sin_addr);
        sock_dst4->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(dst_hit, &sock_dst4->sin_addr);
        sa_size               = sizeof(struct sockaddr_in);
        HIP_DEBUG_LSI("src4 addr ", &(sock_src4->sin_addr));
        HIP_DEBUG_LSI("dst4 addr ", &(sock_dst4->sin_addr));
    } else {
        sock_src6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
        sock_dst6->sin6_family = AF_INET6;
        ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
        sa_size                = sizeof(struct sockaddr_in6);
        is_ipv6                = 1;
        HIP_DEBUG_HIT("src6 addr ", &(sock_src6->sin6_addr));
        HIP_DEBUG_HIT("dst6 addr ", &(sock_dst6->sin6_addr));
    }

    switch (proto) {
    case IPPROTO_TCP:
        _HIP_DEBUG("IPPROTO_TCP\n");
        ((struct tcphdr *) msg)->check = htons(0);
        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_tcp_v6;
            ((struct tcphdr *) msg)->check
                    = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr,
                                       &sock_dst6->sin6_addr, msg, len);
        } else {
            firewall_raw_sock = firewall_raw_sock_tcp_v4;
            ((struct tcphdr *) msg)->check
                    = ipv4_checksum(IPPROTO_TCP, (uint8_t *) &(sock_src4->sin_addr),
                                       (uint8_t *) &(sock_dst4->sin_addr), msg, len);
        }
        break;
    case IPPROTO_UDP:
        HIP_DEBUG("IPPROTO_UDP\n");
        HIP_DEBUG("src_port is %d\n", ntohs(((struct udphdr *) msg)->source));
        HIP_DEBUG("dst_port is %d\n", ntohs(((struct udphdr *) msg)->dest));
        HIP_DEBUG("checksum is %x\n", ntohs(((struct udphdr *) msg)->check));
        ((struct udphdr *) msg)->check = htons(0);
        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_udp_v6;
            ((struct udphdr *) msg)->check
                    = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr,
                                       &sock_dst6->sin6_addr, msg, len);
        } else {
            firewall_raw_sock = firewall_raw_sock_udp_v4;
            ((struct udphdr *) msg)->check
                    = ipv4_checksum(IPPROTO_UDP, (uint8_t *) &(sock_src4->sin_addr),
                                       (uint8_t *) &(sock_dst4->sin_addr), msg, len);
        }
        break;
    case IPPROTO_ICMP:
        ((struct icmphdr *) msg)->checksum = htons(0);
        ((struct icmphdr *) msg)->checksum = inchksum(msg, len);

        if (is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_icmp_outbound;
        } else {
            firewall_raw_sock = firewall_raw_sock_icmp_v4;
        }

        break;
    case IPPROTO_ICMPV6:
        firewall_raw_sock = firewall_raw_sock_icmp_v6;
        ((struct icmp6_hdr *) msg)->icmp6_cksum = htons(0);
        ((struct icmp6_hdr *) msg)->icmp6_cksum
                = ipv6_checksum(IPPROTO_ICMPV6, &sock_src6->sin6_addr,
                                   &sock_dst6->sin6_addr, msg, len);
        break;

    case IPPROTO_ESP:
        if (!is_ipv6) {
            firewall_raw_sock = firewall_raw_sock_esp_v4;
        }
        break;
    default:
        HIP_DEBUG("No protocol family found\n");
        goto out_err;
        break;
    }


    HIP_IFEL(bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size),
             -1, "Binding to raw sock failed\n");
    sent = sendto(firewall_raw_sock, msg, len, 0,
                  (struct sockaddr *) &dst, sa_size);
    if (sent != len) {
        HIP_ERROR("Could not send the all requested" \
                  " data (%d/%d): %s\n", sent, len, strerror(errno));
    } else {
        HIP_DEBUG("sent=%d/%d \n",
                  sent, len);
    }

out_err:
    /* Reset the interface to wildcard*/
    if (is_ipv6) {
        ipv6_addr_copy(&sock_src6->sin6_addr, &any);
    } else {
        sock_src4->sin_addr.s_addr = INADDR_ANY;
        sock_src4->sin_family      = AF_INET;
    }

    bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
    if (err) {
        HIP_DEBUG("sterror %s\n", strerror(errno));
    }

    return err;
}
