/*
 * HIP cookie handling
 * 
 * Licence: GNU/GPL
 * Authors: Kristian Slavov <ksl@iki.fi>
 *          Miika Komu <miika@iki.fi>
 *
 */

#include "cookie.h"

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
//struct hip_r1entry *hip_r1table;

/**
 * hip_calc_cookie_idx - get an index
 * @ip_i: Initiator's IPv6 address
 * @ip_r: Responder's IPv6 address
 *
 * Return 0 <= x < HIP_R1TABLESIZE
 */
static int hip_calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r)
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

#if 0
/**
 * hip_create_new_puzzle - Create/Change the puzzle in R1
 * @pz: Old puzzle
 * @r1: R1entry 
 * @tv: Timevalue, that is inserted into the opaque field in puzzle
 *
 * Stores the old K, I and opaque values and generates new ones.
 * Storing is required since we need to support puzzles sent just before
 * we decide to change the puzzle.
 */
static void hip_create_new_puzzle(struct hip_puzzle *pz, struct hip_r1entry *r1,
				  struct timeval *tv)
{
	uint64_t random_i;

	r1->Ck = pz->K;
	r1->Ci = pz->I;
	memcpy(r1->Copaque, pz->opaque, 3);

	get_random_bytes(&random_i, sizeof(uint64_t));
	pz->I = random_i;
	tv->tv_sec &= 0xFFFFFF;
	pz->opaque[0] = (tv->tv_sec & 0xFF);
	pz->opaque[1] = ((tv->tv_sec >> 8) & 0xFF);
	pz->opaque[2] = ((tv->tv_sec >> 16) & 0xFF);		
}
#endif

/**
 * hip_fetch_cookie_entry - Get a copy of R1entry structure
 * @ip_i: Initiator's IPv6
 * @ip_r: Responder's IPv6
 *
 * Comments for the #if 0 code are inlined below. 
 * 
 * Returns NULL if error.
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r, struct in6_addr *our_hit)
{
#if 0
	struct timeval tv;
	struct hip_puzzle *pz;
	int diff, ts;
#endif
	struct hip_common *err = NULL, *r1 = NULL;
	struct hip_r1entry * hip_r1table;
	struct hip_host_id_entry *hid;
	int idx, len;	

	/* Find the proper R1 table and copy the R1 message from the table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);	
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO)), 
		 NULL, "Requested source HIT no more available.\n");
	hip_r1table = hid->r1;

	idx = hip_calc_cookie_idx(ip_i, ip_r);
	HIP_DEBUG("Calculated index: %d\n", idx);
	//r1 = &hip_r1table[idx];

	/* the code under #if 0 periodically changes the puzzle. It is not included
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
	//ts |= ((int)pz->opaque[2] << 16);

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
//	r1 = HIP_MALLOC(sizeof(struct hip_r1entry), GFP_KERNEL);
//	memcpy(r1, &hip_r1table[idx], sizeof(struct hip_r1entry));
	len = hip_get_msg_total_len(hip_r1table[idx].r1);
	r1 = HIP_MALLOC(len, GFP_KERNEL);
	memcpy(r1, hip_r1table[idx].r1, len);
	err = r1;

 out_err:	
//	if (!err && r1 && r1->r1)
//		HIP_FREE(r1->r1);
	if (!err && r1)
		HIP_FREE(r1);

	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
}


/**
 * hip_solve_puzzle - Solve puzzle.
 * @puzzle_or_solution: Either a pointer to hip_puzzle or hip_solution structure
 * @hdr: The incoming R1/I2 packet header.
 * @mode: Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
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
	uint64_t mask;
	uint64_t randval;
	uint64_t maxtries = 0;
	uint64_t digest = 0;
	u8 cookie[48];
	u8 max_k;
#ifdef __KERNEL__
	struct scatterlist sg[2];
	unsigned int nsg = 2;
#endif
	int err = 0;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	_HIP_DEBUG("\n");
	/* pre-create cookie */
	u = puzzle_or_solution;

#if defined(CONFIG_SYSCTL) || defined(CONFIG_SYSCTL_MODULE)
	max_k = hip_sysconfig_get_max_k();
#else
	max_k = 20;
#endif
	HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
	HIP_IFEL(u->pz.K > max_k, 0, 
		 "Cookie K %u is higher than we are willing to calculate"
		 " (current max K=%d)\n", u->pz.K, max_k);

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

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

#ifdef __KERNEL__
	/* pre map the memory region (for SHA) */
	HIP_IFEL(hip_map_virtual_to_pages(sg, &nsg, cookie, 48) || nsg < 1, 0,
		 "Error mapping virtual addresses to physical pages\n");
#endif

	HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]... 
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0) {
	 	u8 sha_digest[HIP_AH_SHA_LEN];
		
		/* must be 8 */
		memcpy(cookie + 40, (u8*) &randval, sizeof(uint64_t));
#ifdef __KERNEL__
		hip_build_digest_repeat(impl_sha1, sg, nsg, sha_digest);
#else
		hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);
#endif
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

/*
 * @sign the signing function to use
 */
int hip_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     struct hip_host_id *privkey, struct hip_host_id *pubkey)
{
	int i=0;

	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		r1table[i].r1 = hip_create_r1(hit, sign, privkey, pubkey);
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
 * hip_get_r1 - Fetch a precreated R1 and return it.
 * @ip_i: Initiator's IPv6 address
 * @ip_r: Responder's IPv6 address
 * 
 */
#if 0
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r,
			      struct in6_addr *our_hit)
{
	struct hip_r1entry *err;
	struct hip_host_id_entry *hid;

	/* Find the proper R1 table */
	hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO);
	HIP_IFEL(!hid || !(err = hip_fetch_cookie_entry(hid->r1, ip_i, ip_r)), NULL, 
		 "No matching entry\n");

 out_err:
	if (err) {
		
	}

	if (r1e == NULL)
		return NULL;

	return r1e->r1;
}
#endif

#if 0
int hip_verify_generation(struct in6_addr *ip_i, struct in6_addr *ip_r,
			  uint64_t birthday)
{
#if 0
	uint64_t generation;
#endif
	struct hip_r1entry *r1e;

	r1e = hip_fetch_cookie_entry(ip_i, ip_r);
	if (r1e == NULL)
		return -ENOENT;

	/* if we some day support changing the puzzle, we could take
	   the generation into account when veifrying packets etc...
	*/
#if 0
	generation = ((uint64_t)load_time) << 32 | r1e->generation;

	if (birthday + 1 < generation) {
		HIP_ERROR("R1 generation too old\n");
		return -EINVAL;
	}

	if (birthday > generation) {
		HIP_ERROR("R1 generation from future\n");
		return -EINVAL;
	}
#endif
	return 0;
}
#endif

/**
 * hip_verify_cookie - Verify solution to the puzzle
 * @ip_i: Initiator's IPv6
 * @ip_r: Responder's IPv6
 * @hdr: Received HIP packet
 * @solution: Solution structure
 *
 * First we check that K and I are the same as in the puzzle we sent.
 * If not, then we check the previous ones (since the puzzle might just
 * have been expired). 
 *
 * Returns 1 if puzzle ok, 0 if !ok.
 */ 
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr,
		      struct hip_solution *solution)
{
	struct hip_puzzle *puzzle;
	struct hip_r1entry *result;
	struct hip_host_id_entry *hid;
	int err;

	/* Find the proper R1 table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, &hdr->hitr, HIP_ANY_ALGO)), 
		 0, "Requested source HIT not (any more) available.\n");
	result = &hid->r1[hip_calc_cookie_idx(ip_i, ip_r)];

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

	_HIP_HEXDUMP("opaque in solution", solution->opaque, 3);
	_HIP_HEXDUMP("opaque in result", result->Copaque, 3);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque, 3);

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
		HIP_IFEL(solution->I != puzzle->I, 0,
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque, 3), 0, 
			 "Solution's opaque data does not match the opaque data sent\n");
	}
	HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), 1, 
		 "Puzzle incorrectly solved\n");
 out_err:
	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
}

#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
