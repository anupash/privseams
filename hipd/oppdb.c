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
 * Opportunistic mode databases for lib/opphip and HIP registration. The system-based
 * opportunistic mode in the firewall uses also this functionality to trigger an
 * opportunistic base base exchange. See the following publication on the details:
 *
 * <a href="http://www.iki.fi/miika/docs/ccnc09.pdf">
 * Miika Komu and Janne Lindqvist, Leap-of-Faith Security is Enough
 * for IP Mobility, 6th Annual IEEE Consumer
 * Communications & Networking Conference IEEE CCNC 2009, Las Vegas,
 * Nevada, January 2009</a>
 *
 * The pseudo HIT is mentioned on multiple places in this file. When hipd sends
 * the opportunistic I1, the destination HIT is NULL. For this reason, we don't
 * know the Responder HIT until receiving the R2. During this unawareness period,
 * we use a "pseudo HIT" to denote the Responder. It is calculated by extracting
 * part of the IP address of the Responder and prefixing it with HIT prefix and some
 * additional zeroes. Once the R1 received, the opportunistic database entry can
 * be removed and the pseudo HIT becomes unnecessary. Consequtive opportunistic
 * mode connections with the same Responder are cached and the pseudo HIT is not needed.
 *
 * The opportunistic mode supports also "fallback" which occurs with
 * peers that do not support HIP. When the peer does not support HIP,
 * hipd notices it after a certain time out in maintenance.c loop
 * because there was no R1 response. The handlers in this function
 * then send a "reject" message to the blocked opportunistic library
 * process which means that it should proceed without HIP. Consequtive
 * rejects are faster because they are cached.
 *
 * @author Bing Zhou <bingzhou@cc.hut.fi>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/lhash.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/hit.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "config.h"
#include "accessor.h"
#include "hadb.h"
#include "hidb.h"
#include "hipd.h"
#include "netdev.h"
#include "oppipdb.h"
#include "output.h"
#include "registration.h"
#include "user.h"
#include "oppdb.h"


#define HIP_LOCK_OPP_INIT(entry)
#define HIP_UNLOCK_OPP_INIT(entry)
#define HIP_LOCK_OPP(entry)
#define HIP_UNLOCK_OPP(entry)
#define HIP_OPPDB_SIZE 533

struct hip_opp_info {
    hip_hit_t       local_hit;
    hip_hit_t       real_peer_hit;
    hip_hit_t       pseudo_peer_hit;
    struct in6_addr local_addr;
    struct in6_addr peer_addr;
};

HIP_HASHTABLE *oppdb;

/**
 * hashing function for the hashtable implementation
 *
 * @param ptr a pointer to a hip_opp_blocking_request structure
 * @return the calculated hash
 */
static unsigned long hip_oppdb_hash_hit(const void *ptr)
{
    const struct hip_opp_blocking_request *entry = ptr;
    uint8_t                                hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, &entry->peer_phit,
                     sizeof(hip_hit_t) + sizeof(struct sockaddr_in6),
                     hash);

    return *((unsigned long *) hash);
}

/**
 * matching function for the hashtable implementation
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1 a pointer to a hip_opp_block structure
 * @param ptr2 a pointer to a hip_opp_block structure
 * @return zero on match or non-zero otherwise
 */
static int hip_oppdb_match_hit(const void *ptr1, const void *ptr2)
{
    const struct hip_opp_blocking_request *b1 = ptr1;
    const struct hip_opp_blocking_request *b2 = ptr2;
    return memcmp(&b1->peer_phit, &b2->peer_phit, sizeof(hip_hit_t) + sizeof(struct sockaddr_in6));
}

/**
 * delete an opportunistic database entry
 *
 * @param entry the entry to be deleted
 */
static void hip_oppdb_del_entry_by_entry(struct hip_opp_blocking_request *entry)
{
    struct hip_opp_blocking_request *deleted;

    HIP_LOCK_OPP(entry);
    deleted = hip_ht_delete(oppdb, entry);
    HIP_UNLOCK_OPP(entry);
    free(deleted);
}

/**
 * expire an opportunistic connection
 *
 * @param opp_entry the entry to be expired
 * @return zero on success or negative on error
 */
int hip_oppdb_entry_clean_up(struct hip_opp_blocking_request *opp_entry)
{
    int err = 0;

    /** @todo this does not support multiple multiple opp
     *  connections: a better solution might be trash collection  */

    HIP_ASSERT(opp_entry);
    hip_del_peer_info(&opp_entry->peer_phit,
                      &opp_entry->our_real_hit);
    hip_oppdb_del_entry_by_entry(opp_entry);
    return err;
}

/**
 * a for-each iterator function for the opportunistic database
 *
 * @param func a callback iterator function
 * @param opaque an extra parameter to be passed to the callback
 * @return zero on success and non-zero on error
 */
int hip_for_each_opp(int (*func)(struct hip_opp_blocking_request *entry,
                                 void *opaq),
                     void *opaque)
{
    int                              i = 0, fail = 0;
    struct hip_opp_blocking_request *this;
    LHASH_NODE                      *item, *tmp;

    if (!func) {
        return -EINVAL;
    }

    HIP_LOCK_HT(&opp_db);
    list_for_each_safe(item, tmp, oppdb, i)
    {
        this = list_entry(item);
        fail = func(this, opaque);
        if (fail) {
            goto out_err;
        }
    }
out_err:
    HIP_UNLOCK_HT(&opp_db);
    return fail;
}

/**
 * an iterator function for uninitializing the opportunistic database
 *
 * @param entry the entry to be uninitialized
 * @param arg   needed because of the iterator signature
 * @return zero
 */
static int hip_oppdb_uninit_wrap(struct hip_opp_blocking_request *entry,
                                 UNUSED void *arg)
{
    hip_oppdb_del_entry_by_entry(entry);
    return 0;
}

/**
 * uninitialize the whole opportunistic database
 */
void hip_oppdb_uninit(void)
{
    hip_for_each_opp(hip_oppdb_uninit_wrap, NULL);
    hip_ht_uninit(oppdb);
    oppdb = NULL;
}

/**
 * Unblock a caller from the opportunistic library
 *
 * @param app_id the UDP port of the local library process
 * @param opp_info information related to the opportunistic connection
 * @return zero on success or negative on failure
 */
static int hip_opp_unblock_app(const struct sockaddr_in6 *app_id,
                               struct hip_opp_info *opp_info)
{
    struct hip_common *message = NULL;
    int                err     = 0, n;

    HIP_IFEL((app_id->sin6_port == 0), 0, "Zero port, ignore\n");

    HIP_IFE(!(message = hip_msg_alloc()), -1);
    HIP_IFEL(hip_build_user_hdr(message, HIP_MSG_GET_PEER_HIT, 0), -1,
             "build user header failed\n");

    if (!opp_info) {
        goto skip_hit_addr;
    }

    if (!ipv6_addr_any(&opp_info->real_peer_hit)) {
        HIP_IFEL(hip_build_param_contents(message, &opp_info->real_peer_hit,
                                          HIP_PARAM_HIT_PEER,
                                          sizeof(hip_hit_t)), -1,
                 "building peer real hit failed\n");
    }

    if (!ipv6_addr_any(&opp_info->local_hit)) {
        HIP_IFEL(hip_build_param_contents(message, &opp_info->local_hit,
                                          HIP_PARAM_HIT_LOCAL,
                                          sizeof(hip_hit_t)), -1,
                 "building local hit failed\n");
    }

    if (!ipv6_addr_any(&opp_info->peer_addr)) {
        HIP_IFEL(hip_build_param_contents(message, &opp_info->peer_addr,
                                          HIP_PARAM_IPV6_ADDR_PEER,
                                          sizeof(struct in6_addr)), -1,
                 "building peer addr failed\n");
    }

    if (!ipv6_addr_any(&opp_info->local_addr)) {
        HIP_IFEL(hip_build_param_contents(message, &opp_info->local_addr,
                                          HIP_PARAM_IPV6_ADDR_LOCAL,
                                          sizeof(struct in6_addr)), -1,
                 "building local addr failed\n");
    }

skip_hit_addr:

    HIP_DEBUG("Unblocking caller at port %d\n", ntohs(app_id->sin6_port));
    n = hip_sendto_user(message, (const struct sockaddr *) app_id);

    if (n < 0) {
        HIP_ERROR("hip_sendto_user() failed.\n");
        err = -1;
        goto out_err;
    }
out_err:
    free(message);
    return err;
}

/**
 * unblock all opportunistic connections with a certain remote host
 *
 * @param entry the opportunistic mode connection
 * @param ptr the pseudo HIT denoting the remote host
 * @return zero on success or negative on error
 */
static int hip_oppdb_unblock_group(struct hip_opp_blocking_request *entry,
                                   void *ptr)
{
    struct hip_opp_info *opp_info = ptr;
    int                  err      = 0;

    if (ipv6_addr_cmp(&entry->peer_phit, &opp_info->pseudo_peer_hit) != 0) {
        goto out_err;
    }

    HIP_IFEL(hip_opp_unblock_app(&entry->caller, opp_info),
             1, "unblock failed\n");

    hip_oppdb_del_entry_by_entry(entry);

out_err:
    return err;
}

/**
 * create a opportunistic mode database entry
 *
 * @return the created databased entry (caller deallocates)
 */
static struct hip_opp_blocking_request *hip_create_opp_block_entry(void)
{
    struct hip_opp_blocking_request *entry = NULL;

    entry = calloc(1, sizeof(struct hip_opp_blocking_request));
    if (!entry) {
        HIP_ERROR("struct hip_opp_blocking_request memory allocation failed.\n");
        return NULL;
    }

    HIP_LOCK_OPP_INIT(entry);
    time(&entry->creation_time);
    HIP_UNLOCK_OPP_INIT(entry);

    return entry;
}

/**
 * dump the contents of the database
 */
static void hip_oppdb_dump(void)
{
    int                              i;
    struct hip_opp_blocking_request *this;
    LHASH_NODE                      *item, *tmp;

    HIP_DEBUG("start oppdb dump\n");
    HIP_LOCK_HT(&oppdb);

    list_for_each_safe(item, tmp, oppdb, i)
    {
        this = list_entry(item);

        HIP_DEBUG_HIT("this->peer_phit",
                      &this->peer_phit);
        HIP_DEBUG_HIT("this->our_real_hit",
                      &this->our_real_hit);
    }

    HIP_UNLOCK_HT(&oppdb);
    HIP_DEBUG("end oppdb dump\n");
}

/**
 * add an opportunistic mode connection entry to the database
 *
 * @param phit_peer the pseudo HIT of peer
 * @param hit_our local HIT
 * @param ip_peer remote IP address
 * @param ip_our local IP address
 * @param caller the UDP port of the local library process
 * @return zero on success or negative on failure
 */
static int hip_oppdb_add_entry(const hip_hit_t *phit_peer,
                               const hip_hit_t *hit_our,
                               const struct in6_addr *ip_peer,
                               const struct in6_addr *ip_our,
                               const struct sockaddr_in6 *caller)
{
    int                              err      = 0;
    struct hip_opp_blocking_request *new_item = NULL;

    new_item = hip_create_opp_block_entry();
    if (!new_item) {
        HIP_ERROR("new_item malloc failed\n");
        err = -ENOMEM;
        return err;
    }

    if (phit_peer) {
        ipv6_addr_copy(&new_item->peer_phit, phit_peer);
    }
    ipv6_addr_copy(&new_item->our_real_hit, hit_our);
    if (ip_peer) {
        ipv6_addr_copy(&new_item->peer_ip, ip_peer);
    }
    if (ip_our) {
        ipv6_addr_copy(&new_item->our_ip, ip_our);
    }
    memcpy(&new_item->caller, caller, sizeof(struct sockaddr_in6));

    err = hip_ht_add(oppdb, new_item);
    hip_oppdb_dump();

    return err;
}

/**
 * initialize the opportunistic database
 */
void hip_init_opp_db(void)
{
    oppdb = hip_ht_init(hip_oppdb_hash_hit, hip_oppdb_match_hit);
}

/**
 * fetch an hadb entry corresponding to a pseudo HIT
 *
 * @param init_hit the local HIT of the Initiator
 * @param resp_addr the remote IP address of the Responder from
 *                  which to calculate the pseudo HIT
 * @return a host assocition or NULL if not found
 */
static struct hip_hadb_state *hip_oppdb_get_hadb_entry(hip_hit_t *init_hit,
                                                       struct in6_addr *resp_addr)
{
    struct hip_hadb_state *entry_tmp = NULL;
    hip_hit_t              phit;
    int                    err = 0;

    HIP_DEBUG_HIT("resp_addr=", resp_addr);
    HIP_IFEL(hip_opportunistic_ipv6_to_hit(resp_addr, &phit,
                                           HIP_HIT_TYPE_HASH100), -1,
             "hip_opportunistic_ipv6_to_hit failed\n");

    HIP_ASSERT(hit_is_opportunistic_hit(&phit));

    entry_tmp = hip_hadb_find_byhits(init_hit, &phit);

out_err:
    return entry_tmp;
}

/**
 * find a host association based on I1 or R1 message
 *
 * @param msg the I1 or R2 message
 * @param src_addr the source address of the message
 * @return the host association or NULL if not found
 */
struct hip_hadb_state *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
                                                      struct in6_addr *src_addr)
{
    hip_hdr                type  = hip_get_msg_type(msg);
    struct hip_hadb_state *entry = NULL;

    if (type == HIP_I1) {
        if (!ipv6_addr_is_null(&msg->hitr)) {
            goto out_err;
        }
        hip_get_default_hit(&msg->hitr);
    } else if (type == HIP_R1) {
        entry = hip_oppdb_get_hadb_entry(&msg->hitr, src_addr);
    } else {
        HIP_ASSERT(0);
    }

out_err:
    return entry;
}

/**
 * process an incoming R1 packet for an opportunistic connection
 *
 * @param ctx the packet context
 * @return zero on success or negative on failure
 */
int hip_handle_opp_r1(struct hip_packet_context *ctx)
{
    struct hip_opp_info    opp_info;
    struct hip_hadb_state *opp_entry;
    hip_hit_t              phit;
    int                    err = 0;

    opp_entry = ctx->hadb_entry;

    HIP_DEBUG_HIT("peer hit", &ctx->input_msg->hits);
    HIP_DEBUG_HIT("local hit", &ctx->input_msg->hitr);

    HIP_IFEL(hip_hadb_add_peer_info_complete(&ctx->input_msg->hitr,
                                             &ctx->input_msg->hits,
                                             NULL,
                                             &ctx->dst_addr,
                                             &ctx->src_addr,
                                             NULL),
             -1, "Failed to insert peer map\n");

    HIP_IFEL(!(ctx->hadb_entry = hip_hadb_find_byhits(&ctx->input_msg->hits,
                                                      &ctx->input_msg->hitr)),
             -1, "Did not find opp entry\n");

    HIP_IFEL(hip_init_us(ctx->hadb_entry, &ctx->input_msg->hitr),
             -1, "hip_init_us failed\n");
    /* old HA has state 2, new HA has state 1, so copy it */
    ctx->hadb_entry->state = opp_entry->state;
    /* For service registration routines */
    ctx->hadb_entry->local_controls = opp_entry->local_controls;
    ctx->hadb_entry->peer_controls  = opp_entry->peer_controls;

    if (hip_replace_pending_requests(opp_entry, ctx->hadb_entry) == -1) {
        HIP_DEBUG("RVS: Error moving the pending requests to a new HA");
    }

    HIP_DEBUG_HIT("peer hit", &ctx->input_msg->hits);
    HIP_DEBUG_HIT("local hit", &ctx->input_msg->hitr);

    HIP_IFEL(hip_opportunistic_ipv6_to_hit(&ctx->src_addr, &phit,
                                           HIP_HIT_TYPE_HASH100),
             -1, "pseudo hit conversion failed\n");

    ipv6_addr_copy(&opp_info.real_peer_hit, &ctx->input_msg->hits);
    ipv6_addr_copy(&opp_info.pseudo_peer_hit, &phit);
    ipv6_addr_copy(&opp_info.local_hit, &ctx->input_msg->hitr);
    ipv6_addr_copy(&opp_info.local_addr, &ctx->dst_addr);
    ipv6_addr_copy(&opp_info.peer_addr, &ctx->src_addr);

    hip_for_each_opp(hip_oppdb_unblock_group, &opp_info);
    hip_del_peer_info_entry(opp_entry);

out_err:

    return err;
}

/**
 * add an entry to the opportunistic mode dabase and host association
 * database (with pseudo HIT)
 *
 * @param dst_ip the remote IP address of the Responder
 * @param hit_our the local HIT of the Initiator
 * @param caller the UDP port of the local library process
 * @return the created host association
 */
struct hip_hadb_state *hip_opp_add_map(const struct in6_addr *dst_ip,
                                       const struct in6_addr *hit_our,
                                       const struct sockaddr_in6 *caller)
{
    int                    err = 0;
    struct in6_addr        opp_hit, src_ip;
    struct hip_hadb_state *ha          = NULL;
    hip_oppip_t           *oppip_entry = NULL;

    HIP_DEBUG_IN6ADDR("Peer's IP ", dst_ip);

    HIP_IFEL(hip_select_source_address(&src_ip,
                                       dst_ip), -1,
             "Cannot find source address\n");

    HIP_IFEL(hip_opportunistic_ipv6_to_hit(dst_ip, &opp_hit,
                                           HIP_HIT_TYPE_HASH100),
             -1, "Opp HIT conversion failed\n");

    HIP_ASSERT(hit_is_opportunistic_hit(&opp_hit));

    HIP_DEBUG_HIT("opportunistic hashed hit", &opp_hit);

    if ((oppip_entry = hip_oppipdb_find_byip(dst_ip))) {
        HIP_DEBUG("Old mapping exist \n");

        if ((ha = hip_hadb_find_byhits(hit_our, &opp_hit))) {
            goto out_err;
        }

        HIP_DEBUG("No entry found. Adding new map.\n");
        hip_oppipdb_del_entry_by_entry(oppip_entry, NULL);
    }

    /* No previous contact, new host. Let's do the opportunistic magic */

    err = hip_hadb_add_peer_info_complete(hit_our, &opp_hit, NULL, &src_ip, dst_ip, NULL);

    HIP_IFEL(!(ha = hip_hadb_find_byhits(hit_our, &opp_hit)), -1,
             "Did not find entry\n");

    /* Override the receiving function */
    /* @todo is this function set needed? */
    //ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;

    HIP_IFEL(hip_oppdb_add_entry(&opp_hit, hit_our, dst_ip, &src_ip,
                                 caller), -1, "Add db failed\n");

out_err:
    return ha;
}

/**
 * check if it is time for an opportunistic connection to
 * time out and make it happen when needed
 *
 * @param entry the database entry for the opportunistic connection
 * @param current_time the current time
 * @return zero on success or negative on failure
 */
int hip_handle_opp_fallback(struct hip_opp_blocking_request *entry,
                            void *current_time)
{
    int              err = 0, disable_fallback = 0;
    time_t          *now = current_time;
    struct in6_addr *addr;

    if (!disable_fallback && (*now - HIP_OPP_WAIT > entry->creation_time)) {
        struct hip_opp_info info;

        memset(&info, 0, sizeof(info));
        ipv6_addr_copy(&info.peer_addr, &entry->peer_ip);

        addr = &entry->peer_ip;
        hip_oppipdb_add_entry(addr);
        HIP_DEBUG("Timeout for opp entry, falling back to\n");
        err = hip_opp_unblock_app(&entry->caller, &info);
        HIP_DEBUG("Fallback returned %d\n", err);
        err = hip_oppdb_entry_clean_up(entry);
        memset(&now, 0, sizeof(now));
    }

    return err;
}

/**
 * check if a remote host is not capable of HIP
 *
 * @param ip_peer: pointer to the ip of the host to check whether
 *                 it is HIP capable or not
 * @return pointer to the entry if the remote host does not definitely support HIP or
 *         NULL if it is potentially HIP capable
 */
struct hip_opp_blocking_request *hip_oppdb_find_by_ip(const struct in6_addr *ip_peer)
{
    int                              i = 0;
    struct hip_opp_blocking_request *this, *ret = NULL;
    LHASH_NODE                      *item, *tmp;

    if (oppdb == NULL) {
        return NULL;
    }

    HIP_LOCK_HT(&opp_db);
    list_for_each_safe(item, tmp, oppdb, i)
    {
        this = list_entry(item);
        if (ipv6_addr_cmp(&this->peer_ip, ip_peer) == 0) {
            HIP_DEBUG("The ip was found in oppdb. Peer non-HIP capable.\n");
            ret = this;
            break;
        }
    }

    HIP_UNLOCK_HT(&opp_db);
    return ret;
}

/**
 * Trigger opportunistic I1 to obtain the HIT of the Responder.
 *
 * @param msg contains information on the Responder's IP address
 *            and the local HIT to use for the connection
 * @param src the UDP port number of the calling library process
 * @return zero on success or negative on failure
 */
int hip_opp_get_peer_hit(struct hip_common *msg,
                         const struct sockaddr_in6 *src)
{
    int                    err = 0;
    struct in6_addr        phit, dst_ip, our_hit, our_addr;
    const struct in6_addr *ptr;
    struct hip_hadb_state *ha;

    ptr = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
    HIP_IFEL(!ptr, -1, "No local hit in msg\n");
    memcpy(&our_hit, ptr, sizeof(our_hit));
    HIP_DEBUG_HIT("our_hit", &our_hit);

    ptr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);
    HIP_IFEL(!ptr, -1, "No peer ip in msg\n");
    memcpy(&dst_ip, ptr, sizeof(dst_ip));
    HIP_DEBUG_HIT("dst_ip", &dst_ip);

    HIP_IFEL(hip_select_source_address(&our_addr, &dst_ip),
             -1, "Cannot find source address\n");

    /* Check if we've previously contacted the host and found it
     * non-HIP capable*/
    if (hip_oppipdb_find_byip(&dst_ip)) {
        hip_msg_init(msg);
        /* A message without peer HIT indicates a non-HIP capable peer */
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_PEER_HIT, 0), -1,
                 "Building of user header failed\n");
        HIP_IFEL(hip_build_param_contents(msg,
                                          &dst_ip,
                                          HIP_PARAM_IPV6_ADDR_PEER,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT  failed: %s\n");
        HIP_IFEL((hip_sendto_user(msg, (const struct sockaddr *) src) < 0),
                 -1, "send to user failed\n");
        goto out_err;
    }

    /* No previous contact, new host. Let's do the opportunistic magic */

    HIP_IFEL(hip_opportunistic_ipv6_to_hit(&dst_ip, &phit,
                                           HIP_HIT_TYPE_HASH100),
             -1, "Opp HIT conversion failed\n");

    HIP_ASSERT(hit_is_opportunistic_hit(&phit));

    HIP_DEBUG_HIT("phit", &phit);

    hip_hadb_add_peer_info_complete(&our_hit,  &phit,   NULL,
                                    &our_addr, &dst_ip, NULL);

    HIP_IFEL(!(ha = hip_hadb_find_byhits(&our_hit, &phit)),
             -1, "Did not find hadb entry\n");

    HIP_IFEL(hip_oppdb_add_entry(&phit, &our_hit, &dst_ip, NULL, src),
             -1, "Add to oppdb failed\n");

    HIP_IFEL(hip_send_i1(&our_hit, &phit, ha), -1, "sending of I1 failed\n");

out_err:
    return err;
}
