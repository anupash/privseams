/*
 * HIP cookie handling
 * 
 * Licence: GNU/GPL
 * Authors: Kristian Slavov <ksl@iki.fi>
 *          Miika Komu <miika@iki.fi>
 *
 */

#include "cookie.h"

int hip_cookie_difficulty = HIP_DEFAULT_COOKIE_K;

#ifndef CONFIG_HIP_ICOOKIE /* see also spam.c for overriding functions */

void hip_init_puzzle_defaults() {
	return;
}

int hip_get_cookie_difficulty(hip_hit_t *not_used) {
	/* Note: we could return a higher value if we detect DoS */
	return hip_cookie_difficulty;
}

int hip_set_cookie_difficulty(hip_hit_t *not_used, int k) {
	if (k > HIP_PUZZLE_MAX_K || k < 1) {
		HIP_ERROR("Bad cookie value (%d), min=%d, max=%d\n",
			  k, 1, HIP_PUZZLE_MAX_K);
		return -1;
	}
	hip_cookie_difficulty = k;
	HIP_DEBUG("HIP cookie value set to %d\n", k);
	return k;
}

int hip_inc_cookie_difficulty(hip_hit_t *not_used) {
	int k = hip_get_cookie_difficulty(NULL) + 1;
	return hip_set_cookie_difficulty(NULL, k);
}

int hip_dec_cookie_difficulty(hip_hit_t *not_used) {
	int k = hip_get_cookie_difficulty(NULL) - 1;
	return hip_set_cookie_difficulty(NULL, k);
}

/**
 * hip_calc_cookie_idx - get an index
 * @param ip_i Initiator's IPv6 address
 * @param ip_r Responder's IPv6 address
 * @param hit_i Initiators HIT
 *
 * Return 0 <= x < HIP_R1TABLESIZE
 */
int hip_calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r,
			       struct in6_addr *hit_i)
{
	register u32 base=0;
	int i;

	for(i = 0; i < 4; i++) {
		base ^= ip_i->s6_addr32[i];
		base ^= ip_r->s6_addr32[i];
	}

	for(i = 0; i < 3; i++) {
		base ^= ((base >> (24 - i * 8)) & 0xFF);
	}

	/* base ready */

	return (base) % HIP_R1TABLESIZE;
}
#endif /* !CONFIG_HIP_ICOOKIE */

/**
 * hip_fetch_cookie_entry - Get a copy of R1entry structure
 * @param ip_i Initiator's IPv6
 * @param ip_r Responder's IPv6
 *
 * Comments for the if 0 code are inlined below. 
 * 
 * Returns NULL if error.
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r,
			      struct in6_addr *our_hit,
			      struct in6_addr *peer_hit)
{
	struct hip_common *err = NULL, *r1 = NULL;
	struct hip_r1entry * hip_r1table;
	struct hip_host_id_entry *hid;
	int idx, len;

	/* Find the proper R1 table and copy the R1 message from the table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);	
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO, -1)), 
		 NULL, "Requested source HIT no more available.\n");
	HIP_DEBUG("!!!!!!!!! Is Requested source HIT available?");
	hip_r1table = hid->r1;

	idx = hip_calc_cookie_idx(ip_i, ip_r, peer_hit);
	HIP_DEBUG("Calculated index: %d\n", idx);

	/* the code under if 0 periodically changes the puzzle. It is not included
	   in compilation as there is currently no easy way of signing the R1 packet
	   after having changed its puzzle.
	*/
#if 0
	/* generating opaque data */
	do_gettimeofday(&tv);

	/* extract the puzzle */
	if (!(pz = hip_get_param(err->r1, HIP_PARAM_PUZZLE)), NULL, 
	    "Internal error: Could not find PUZZLE parameter in precreated R1 packet\n");

	ts = pz->opaque[0];
	ts |= ((int)pz->opaque[1] << 8);

	if (ts != 0) {
		/* check if the cookie is too old */
		diff = (tv.tv_sec & 0xFFFFFF) - ts;
		if (diff < 0)
			diff += 0x1000000;

		HIP_DEBUG("Old puzzle still valid\n");
		if (diff <= HIP_PUZZLE_MAX_LIFETIME)
			return err;
	}

	/* either ts == 0 or diff > HIP_PUZZLE_MAX_LIFETIME */
	_HIP_DEBUG("Creating new puzzle\n");
	hip_create_new_puzzle(pz, r1, &tv);

	/* XXX: sign the R1 */
#endif
	/* Create a copy of the found entry */
	len = hip_get_msg_total_len(hip_r1table[idx].r1);
	/* Replaced memory allocation, Lauri Silvennoinen 02.08.2006 */
        //r1 = HIP_MALLOC(len, GFP_KERNEL);
	r1 = hip_msg_alloc();
	memcpy(r1, hip_r1table[idx].r1, len);
	err = r1;

 out_err:	
	if (!err && r1)
		HIP_FREE(r1);

	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
}


/**
 * hip_solve_puzzle - Solve puzzle.
 * @param puzzle_or_solution Either a pointer to hip_puzzle or hip_solution structure
 * @param hdr The incoming R1/I2 packet header.
 * @param mode Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * The K and I is read from the @puzzle_or_solution. 
 *
 * The J that solves the puzzle is returned, or 0 to indicate an error.
 * NOTE! I don't see why 0 couldn't solve the puzzle too, but since the
 * odds are 1/2^64 to try 0, I don't see the point in improving this now.
 */
uint64_t hip_solve_puzzle(void *puzzle_or_solution, struct hip_common *hdr,
			  int mode)
{
	uint64_t mask = 0;
	uint64_t randval = 0;
	uint64_t maxtries = 0;
	uint64_t digest = 0;
	u8 cookie[48];
	int err = 0;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	HIP_HEXDUMP("puzzle", puzzle_or_solution,
		    (mode == HIP_VERIFY_PUZZLE ? sizeof(struct hip_solution) : sizeof(struct hip_puzzle)));

	_HIP_DEBUG("\n");
	/* pre-create cookie */
	u = puzzle_or_solution;

	_HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
	HIP_IFEL(u->pz.K > HIP_PUZZLE_MAX_K, 0, 
		 "Cookie K %u is higher than we are willing to calculate"
		 " (current max K=%d)\n", u->pz.K, HIP_PUZZLE_MAX_K);

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

	HIP_DEBUG("(u->pz.I: 0x%llx\n", u->pz.I);

	if (mode == HIP_VERIFY_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hits);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hitr);
		//randval = ntoh64(u->sl.J);
		randval = u->sl.J;
		HIP_DEBUG("u->sl.J: 0x%llx\n", randval);
		maxtries = 1;
	} else if (mode == HIP_SOLVE_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hitr);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hits);
		maxtries = 1ULL << (u->pz.K + 2); /* fix */
		get_random_bytes(&randval, sizeof(u_int64_t));
	} else {
		HIP_IFEL(1, 0, "Unknown mode: %d\n", mode);
	}

	HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]... 
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0) {
	 	u8 sha_digest[HIP_AH_SHA_LEN];
		
		/* must be 8 */
		memcpy(cookie + 40, (u8*) &randval, sizeof(uint64_t));

		hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);

                /* copy the last 8 bytes for checking */
		memcpy(&digest, sha_digest + 12, sizeof(uint64_t));

		/* now, in order to be able to do correctly the bitwise
		 * AND-operation we have to remember that little endian
		 * processors will interpret the digest and mask reversely.
		 * digest is the last 64 bits of the sha1-digest.. how that is
		 * ordered in processors registers etc.. does not matter to us.
		 * If the last 64 bits of the sha1-digest is
		 * 0x12345678DEADBEEF, whether we have 0xEFBEADDE78563412
		 * doesn't matter because the mask matters... if the mask is
		 * 0x000000000000FFFF (or in other endianness
		 * 0xFFFF000000000000). Either ways... the result is
		 * 0x000000000000BEEF or 0xEFBE000000000000, which the cpu
		 * interprets as 0xBEEF. The mask is converted to network byte
		 * order (above).
		 */
		if ((digest & mask) == 0) {
			HIP_DEBUG("*** Puzzle solved ***: 0x%llx\n",randval);
			_HIP_HEXDUMP("digest", sha_digest, HIP_AH_SHA_LEN);
			_HIP_HEXDUMP("cookie", cookie, sizeof(cookie));
			return randval;
		}

		/* It seems like the puzzle was not correctly solved */
		HIP_IFEL(mode == HIP_VERIFY_PUZZLE, 0, "Puzzle incorrect\n");
		randval++;
	}

	HIP_ERROR("Could not solve the puzzle, no solution found\n");
 out_err:
	return err;
}


struct hip_r1entry * hip_init_r1(void)
{
	struct hip_r1entry *err;

	HIP_IFE(!(err = (struct hip_r1entry *)HIP_MALLOC(sizeof(struct hip_r1entry) * HIP_R1TABLESIZE,
							 GFP_KERNEL)), NULL); 
	memset(err, 0, sizeof(struct hip_r1entry) * HIP_R1TABLESIZE);

 out_err:
	return err;
}


#ifndef CONFIG_HIP_ICOOKIE
/*
 * @sign the signing function to use
 */
int hip_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     struct hip_host_id *privkey, struct hip_host_id *pubkey)
{
	int i=0;
	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		int cookie_k;

		cookie_k = hip_get_cookie_difficulty(NULL);

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
#endif /* !CONFIG_HIP_ICOOKIE */

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
		for(i=0; i < HIP_R1TABLESIZE; i++) {
			if (hip_r1table[i].r1) {
				HIP_FREE(hip_r1table[i].r1);
			}
		}
		HIP_FREE(hip_r1table);
	}
}

/**
 * hip_verify_cookie - Verify solution to the puzzle
 * @param ip_i Initiator's IPv6
 * @param ip_r Responder's IPv6
 * @param hdr Received HIP packet
 * @param solution Solution structure
 *
 * First we check that K and I are the same as in the puzzle we sent.
 * If not, then we check the previous ones (since the puzzle might just
 * have been expired). 
 *
 * Returns 1 if puzzle ok, 0 if !ok.
 */ 
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr, struct hip_solution *solution)
{
	struct hip_puzzle *puzzle;
	struct hip_r1entry *result;
	struct hip_host_id_entry *hid;
	int err = 1;

	/* Find the proper R1 table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, &hdr->hitr, HIP_ANY_ALGO, -1)), 
		 0, "Requested source HIT not (any more) available.\n");
	result = &hid->r1[hip_calc_cookie_idx(ip_i, ip_r, &hdr->hits)];

	puzzle = hip_get_param(result->r1, HIP_PARAM_PUZZLE);
	HIP_IFEL(!puzzle, 0, "Internal error: could not find the cookie\n");

	_HIP_HEXDUMP("opaque in solution", solution->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in result", result->Copaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);

	HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
			HIP_PUZZLE_OPAQUE_LEN), 0, 
		 "Received cookie opaque does not match the sent opaque\n");

	HIP_DEBUG("Solution's I (0x%llx), sent I (0x%llx)\n",
		  solution->I, puzzle->I);

	_HIP_HEXDUMP("opaque in solution", solution->opaque, 
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in result", result->Copaque, 
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque, 
		     HIP_PUZZLE_OPAQUE_LEN);

	if (solution->K != puzzle->K) {
		HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
			 solution->K, puzzle->K);
		
		HIP_IFEL(solution->K != result->Ck, 0,
			"Solution's K did not match any sent Ks.\n");
		HIP_IFEL(solution->I != result->Ci, 0, 
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, result->Copaque, HIP_PUZZLE_OPAQUE_LEN), 0,
			 "Solution's opaque data does not match sent opaque data\n");
		HIP_DEBUG("Received solution to an old puzzle\n");

	} else {
		HIP_HEXDUMP("solution", solution, sizeof(*solution));
		HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
		HIP_IFEL(solution->I != puzzle->I, 0,
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
				HIP_PUZZLE_OPAQUE_LEN), 0, 
			 "Solution's opaque data does not match the opaque data sent\n");
	}

	HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), 0, 
	 "Puzzle incorrectly solved\n");
	
 out_err:
	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
}

int hip_recreate_r1s_for_entry(struct hip_host_id_entry *entry, void *not_used)
{
	struct hip_host_id *private = NULL;
	struct hip_lhi lhi;
	int err = 0, len;

	/* Store private key and lhi, delete the host id entry and readd.
	   Addition recreates also R1s as a side effect.*/ 

	len = hip_get_param_total_len(entry->host_id);
	HIP_IFEL(!(private = (struct hip_host_id *) HIP_MALLOC(len, 0)), 
		 -ENOMEM, "pubkey mem alloc failed\n");
	memcpy(private, entry->host_id, len);

	memcpy(&lhi, &entry->lhi, sizeof(lhi));

	HIP_IFEL(hip_del_host_id(HIP_DB_LOCAL_HID, &lhi), -1,
		 "Failed to delete host id\n");

	HIP_IFEL(hip_add_host_id(HIP_DB_LOCAL_HID, &lhi, private, 
				 NULL, NULL, NULL),
		 -EFAULT, "adding of local host identity failed\n");

 out_err:
	if (private)
		free(private);
	return err;
}

int hip_recreate_all_precreated_r1_packets()
{
	return hip_for_each_hi(hip_recreate_r1s_for_entry, NULL);
}
