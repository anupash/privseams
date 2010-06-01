/**
 * @file
 * HIP cookie handling
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @author Kristian Slavov <ksl#iki.fi>
 * @author Miika Komu <miika#iki.fi>
 *
 */

#define _BSD_SOURCE

#include <stdlib.h>

#include "config.h"
#include "cookie.h"
#include "lib/core/solve.h"

#define HIP_PUZZLE_MAX_LIFETIME 60 /* in seconds */
#define HIP_DEFAULT_COOKIE_K    1ULL /* a difficulty of i leads to approx. 2^(i-1) hash computations during BEX */

int hip_cookie_difficulty = HIP_DEFAULT_COOKIE_K;

/* forwards */
static int hip_get_cookie_difficulty(hip_hit_t *not_used);
static int hip_set_cookie_difficulty(hip_hit_t *not_used, int k);

/**
 * get the puzzle difficulty and return result (for hipconf)
 *
 * @param msg A message containing a HIT for which to query for
 *            the difficulty. The difficulty will be written
 *            into the message as a HIP_PARAM_INT parameter.
 * @return zero on success and negative on error
 */
int hip_get_puzzle_difficulty_msg(struct hip_common *msg)
{
    int err            = 0, diff = 0;
    hip_hit_t *dst_hit = NULL;
    hip_hit_t all_zero_hit;
    bzero(&all_zero_hit, sizeof(all_zero_hit));

    /* obtain the hit */
    dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);

    diff = hip_get_cookie_difficulty(NULL);

    hip_build_param_contents(msg, &diff, HIP_PARAM_INT, sizeof(diff));

    return err;
}


/**
 * set the puzzle difficulty according to the msg sent by hipconf
 *
 * @param msg An input/output message. Should contain the target
 *            HIT and the required puzzle difficulty.
 * @return zero on success and negative on error
 */
int hip_set_puzzle_difficulty_msg(struct hip_common *msg)
{
    int err = 0, *newVal = NULL;
    hip_hit_t *dst_hit = NULL;
    hip_hit_t all_zero_hit;
    bzero(&all_zero_hit, sizeof(all_zero_hit));

    HIP_IFEL(!(dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT)),
             -1, "No HIT set\n");
    HIP_IFEL(!(newVal = hip_get_param_contents(msg, HIP_PARAM_INT)),
             -1, "No difficulty set\n");

    HIP_IFEL(hip_set_cookie_difficulty(NULL, *newVal), -1,
             "Setting difficulty failed\n");
 out_err:
    return err;
}

/**
 * query for current puzzle difficulty
 *
 * @param not_used not used
 * @return the puzzle difficulty
 */
static int hip_get_cookie_difficulty(hip_hit_t *not_used)
{
    /* Note: we could return a higher value if we detect DoS */
    return hip_cookie_difficulty;
}

/**
 * set puzzle difficulty
 *
 * @param not_used not used
 * @param k the new puzzle difficulty
 * @return the k value on success or negative on error
 */
static int hip_set_cookie_difficulty(hip_hit_t *not_used, int k)
{
    if (k > HIP_PUZZLE_MAX_K || k < 1) {
        HIP_ERROR("Bad cookie value (%d), min=%d, max=%d\n",
                  k, 1, HIP_PUZZLE_MAX_K);
        return -1;
    }
    hip_cookie_difficulty = k;
    HIP_DEBUG("HIP cookie value set to %d\n", k);
    return k;
}

/**
 * increase cookie difficulty by one
 *
 * @param not_used not used
 * @return the new cookie difficulty
 */
int hip_inc_cookie_difficulty(hip_hit_t *not_used)
{
    int k = hip_get_cookie_difficulty(NULL) + 1;
    return hip_set_cookie_difficulty(NULL, k);
}

/**
 * decrease cookie difficulty by one
 *
 * @param not_used not used
 * @return the new cookie difficulty
 */
int hip_dec_cookie_difficulty(hip_hit_t *not_used)
{
    int k = hip_get_cookie_difficulty(NULL) - 1;
    return hip_set_cookie_difficulty(NULL, k);
}

/**
 * calculate the index of a cookie
 *
 * @param ip_i Initiator's IPv6 address
 * @param ip_r Responder's IPv6 address
 * @param hit_i Initiators HIT
 *
 * @return 0 <= x < HIP_R1TABLESIZE
 */
static int hip_calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r,
                               struct in6_addr *hit_i)
{
    register uint32_t base = 0;
    int i;

    for (i = 0; i < 4; i++) {
        base ^= ip_i->s6_addr32[i];
        base ^= ip_r->s6_addr32[i];
    }

    for (i = 0; i < 3; i++) {
        base ^= ((base >> (24 - i * 8)) & 0xFF);
    }

    /* base ready */

    return (base) % HIP_R1TABLESIZE;
}

/**
 * get a copy of R1entry structure
 *
 * @param ip_i Initiator's IPv6
 * @param ip_r Responder's IPv6
 * @param our_hit Our HIT
 * @param peer_hit The peer's HIT
 *
 * @note Comments for the if 0 code are inlined below.
 *
 * Returns NULL if error.
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r,
                              struct in6_addr *our_hit,
                              struct in6_addr *peer_hit)
{
    struct hip_common *err          = NULL, *r1 = NULL;
    struct hip_r1entry *hip_r1table = NULL;
    struct hip_host_id_entry *hid   = NULL;
    int idx, len;

    /* Find the proper R1 table and copy the R1 message from the table */
    HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);
    HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO, -1)),
             NULL, "Unknown HIT\n");

    hip_r1table = hid->r1;
    idx = hip_calc_cookie_idx(ip_i, ip_r, peer_hit);
    HIP_DEBUG("Calculated index: %d\n", idx);

    /* Create a copy of the found entry */
    len = hip_get_msg_total_len(hip_r1table[idx].r1);
    r1  = hip_msg_alloc();
    memcpy(r1, hip_r1table[idx].r1, len);
    err = r1;

out_err:
    if (!err && r1) {
        free(r1);
    }

    HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
    return err;
}

/**
 * initialize an R1 entry structure
 *
 * @return The allocated R1 entry structure. Caller deallocates.
 */
struct hip_r1entry *hip_init_r1(void)
{
    struct hip_r1entry *err;

    HIP_IFE(!(err = malloc(sizeof(struct hip_r1entry) * HIP_R1TABLESIZE)),
            NULL);
    memset(err, 0, sizeof(struct hip_r1entry) * HIP_R1TABLESIZE);

out_err:
    return err;
}

/**
 * precreate an R1 packet
 *
 * @param r1table a pointer to R1 table structure
 * @param hit the local HIT
 * @param sign a signing callback function
 * @param privkey the private key to use for signing
 * @param pubkey the host id (public key)
 * @return zero on success and non-zero on error
 */
int hip_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit,
                     int (*sign)(void *key, struct hip_common *m),
                     void *privkey, struct hip_host_id *pubkey)
{
    int i = 0;
    for (i = 0; i < HIP_R1TABLESIZE; i++) {
        int cookie_k;

        cookie_k      = hip_get_cookie_difficulty(NULL);

        r1table[i].r1 = hip_create_r1(hit, sign, privkey, pubkey,
                                      cookie_k);
        if (!r1table[i].r1) {
            HIP_ERROR("Unable to precreate R1s\n");
            goto err_out;
        }

        HIP_DEBUG("Packet %d created\n", i);
    }

    return 1;

err_out:
    return 0;
}

/**
 * uninitialize R1 table
 *
 * @param hip_r1table R1 table
 */
void hip_uninit_r1(struct hip_r1entry *hip_r1table)
{
    int i;

    /* The R1 packet consist of 2 memory blocks. One contains the actual
     * buffer where the packet is formed, while the other contains
     * pointers to different TLVs to speed up parsing etc.
     * The r1->common is the actual buffer, and r1 is the structure
     * holding only pointers to the TLVs.
     */
    if (hip_r1table) {
        for (i = 0; i < HIP_R1TABLESIZE; i++) {
            if (hip_r1table[i].r1) {
                free(hip_r1table[i].r1);
            }
        }
        free(hip_r1table);
        hip_r1table = NULL;
    }
}

/**
 * Verifies the solution of a puzzle. First we check that K and I are the same
 * as in the puzzle we sent. If not, then we check the previous ones (since the
 * puzzle might just have been expired).
 *
 * @param ip_i     a pointer to Initiator's IP address.
 * @param ip_r     a pointer to Responder's IP address.
 * @param hdr      a pointer to HIP packet common header
 * @param solution a pointer to a solution structure
 * @return         Zero if the cookie was verified succesfully, negative
 *                 otherwise.
 */
int hip_verify_cookie(in6_addr_t *ip_i, in6_addr_t *ip_r,
                      hip_common_t *hdr, struct hip_solution *solution)
{
    /* In a effort to conform the HIPL coding convention, the return value
     * of this function was inverted. I.e. This function now returns
     * negative for error conditions, zero otherwise. It used to be the
     * other way around. -Lauri 23.07.2008. */
    struct hip_puzzle *puzzle     = NULL;
    struct hip_r1entry *result    = NULL;
    struct hip_host_id_entry *hid = NULL;
    int err                       = 0;

    /* Find the proper R1 table */
    HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(
                   HIP_DB_LOCAL_HID, &hdr->hitr, HIP_ANY_ALGO,
                   -1)),
             -1, "Requested source HIT not (any more) available.\n");
    result = &hid->r1[hip_calc_cookie_idx(ip_i, ip_r, &hdr->hits)];

    puzzle = hip_get_param(result->r1, HIP_PARAM_PUZZLE);
    HIP_IFEL(!puzzle, -1, "Internal error: could not find the cookie\n");
    HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
                    HIP_PUZZLE_OPAQUE_LEN), -1,
             "Received cookie opaque does not match the sent opaque\n");

    HIP_DEBUG("Solution's I (0x%llx), sent I (0x%llx)\n",
              solution->I, puzzle->I);

    if (solution->K != puzzle->K) {
        HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
                 solution->K, puzzle->K);

        HIP_IFEL(solution->K != result->Ck, -1,
                 "Solution's K did not match any sent Ks.\n");
        HIP_IFEL(solution->I != result->Ci, -1,
                 "Solution's I did not match the sent I\n");
        HIP_IFEL(memcmp(solution->opaque, result->Copaque,
                        HIP_PUZZLE_OPAQUE_LEN), -1,
                 "Solution's opaque data does not match sent opaque " \
                 "data.\n");
        HIP_DEBUG("Received solution to an old puzzle\n");
    } else {
        HIP_HEXDUMP("solution", solution, sizeof(*solution));
        HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
        HIP_IFEL(solution->I != puzzle->I, -1,
                 "Solution's I did not match the sent I\n");
        HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
                        HIP_PUZZLE_OPAQUE_LEN), -1,
                 "Solution's opaque data does not match the opaque " \
                 "data sent\n");
    }

    HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), -1,
             "Puzzle incorrectly solved.\n");

out_err:

    return err;
}

/**
 * recreate R1 packets corresponding to one HI
 *
 * @param entry the host id entry
 * @param new_hash unused
 * @return zero on success or negative on error
 */
static int hip_recreate_r1s_for_entry_move(struct hip_host_id_entry *entry,
                                           void *new_hash)
{
    int err = 0;

    hip_uninit_r1(entry->r1);
    HIP_IFE(!(entry->r1 = hip_init_r1()), -ENOMEM);
    HIP_IFE(!hip_precreate_r1(entry->r1, &entry->lhi.hit,
                              (hip_get_host_id_algo(entry->host_id) ==
                               HIP_HI_RSA ? hip_rsa_sign : hip_dsa_sign),
                              entry->private_key, entry->host_id), -1);

out_err:
    return err;
}

/**
 * precreate all R1 packets
 *
 * @return zero on success or negative on error
 */
int hip_recreate_all_precreated_r1_packets(void)
{
    HIP_HASHTABLE *ht = hip_ht_init(hip_hidb_hash, hip_hidb_match);
    hip_list_t *curr, *iter;
    struct hip_host_id *tmp;
    int c;

    hip_for_each_hi(hip_recreate_r1s_for_entry_move, ht);

    list_for_each_safe(curr, iter, ht, c)
    {
        tmp = (struct hip_host_id *) list_entry(curr);
        hip_ht_add(HIP_DB_LOCAL_HID, tmp);
        list_del(tmp, ht);
    }

    hip_ht_uninit(ht);
    return 0;
}
