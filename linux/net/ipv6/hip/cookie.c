/*
 * HIP cookie handling
 * 
 * Licence: GNU/GPL
 * Authors: Kristian Slavov <ksl@iki.fi>
 *          Miika Komu <miika@iki.fi>
 *
 */

#include <linux/types.h>
#include <linux/random.h>
#include <asm/scatterlist.h>

#include "cookie.h"
#include "debug.h"
#include "hip.h"
#include "builder.h"
#include "hashtable.h"
#include "misc.h"

HIP_HASHTABLE r1db_hit;
static struct list_head r1db_byhit[HIP_R1DB_SIZE];


static void hip_r1db_hold_entry(void *entry)
{
	HIP_R1E *r1e = entry;

	HIP_ASSERT(entry);
	atomic_inc(&r1e->refcnt);
	HIP_DEBUG("R1DB: %p, refcnt incremented to: %d\n", r1e, atomic_read(&r1e->refcnt));
}

static void hip_r1db_put_entry(void *entry)
{
	HIP_R1E *r1e = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&r1e->refcnt)) {
                HIP_DEBUG("R1DB: %p, refcnt reached zero. Deleting...\n",r1e);
		hip_r1_delete(r1e);
	} else {
                HIP_DEBUG("R1DB: %p, refcnt decremented to: %d\n", r1e, 
			  atomic_read(&r1e->refcnt));
	}
}

static void *hip_r1db_get_key(void *entry)
{
	return (void *)&(((HIP_R1E *)entry)->hit);
}

void hip_init_r1db()
{
	memset(&r1db_hit,0,sizeof(r1db_hit));

	r1db_hit.head = r1db_byhit;
	r1db_hit.hashsize = HIP_R1DB_SIZE;
	r1db_hit.offset = offsetof(HIP_R1E, next_hit);
	r1db_hit.hash = hip_hash_hit;
	r1db_hit.compare = hip_match_hit;
	r1db_hit.hold = hip_r1db_hold_entry;
	r1db_hit.put = hip_r1db_put_entry;
	r1db_hit.get_key = hip_r1db_get_key;

	strncpy(r1db_hit.name, "R1 HASH TABLE", 15);
	r1db_hit.name[15] = 0;

	hip_ht_init(&r1db_hit);
}

void hip_r1_delete(HIP_R1E *entry)
{
	HIP_DEBUG("r1 delete\n");

}

/**
 * hip_r1_find - Get R1E entry corresponding to the argument hit.
 * @hit: Key
 * 
 * If a R1E is found, it is automatically holded (refcnt incremented).
 *
 * Returns the R1E or NULL if R1E was not found.
 */
HIP_R1E *hip_r1_find(struct in6_addr *hit)
{
	HIP_R1E *r1e;

	r1e = hip_ht_find(&r1db_hit, hit);
 	return r1e;
}

int hip_r1_insert(HIP_R1E *r1e)
{
	HIP_R1E *tmp;
	int err;

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&r1e->refcnt) <= 1); 

	if (ipv6_addr_any(&r1e->hit)) {
		HIP_ERROR("Cannot insert RVA entry with NULL hit\n");
		return -EINVAL;
	}

	tmp = hip_ht_find(&r1db_hit, &r1e->hit);
	if (tmp) {
		HIP_INFO("Duplicate entry... not adding to RVA table\n");
		return -EEXIST;
	}

	err = hip_ht_add(&r1db_hit, r1e);
	if (!err)
		r1e->r1estate |= HIP_R1ESTATE_VALID;

	return err;
}

HIP_R1E *hip_allocate_r1db_entry()
{
	HIP_R1E *r1e;
	r1e = kmalloc(sizeof(*r1e), GFP_KERNEL);
	if(!r1e)
		return NULL;
	atomic_set(&r1e->refcnt, 0);
	spin_lock_init(&r1e->r1e_lock);
	memset(r1e->r1table, 0, HIP_R1TABLESIZE*sizeof(struct hip_r1entry));

	return r1e;
}

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
 * hip_fetch_cookie_entry - Get an R1entry structure
 * @ip_i: Initiator's IPv6
 * @ip_r: Responder's IPv6
 *
 * Comments for the #if 0 code are inlined below. 
 * 
 * Returns NULL if error.
 */
static struct hip_r1entry *hip_fetch_cookie_entry(struct in6_addr *ip_i,
						  struct in6_addr *ip_r,
						  struct in6_addr *hit)
{
#if 0
	struct timeval tv;
	struct hip_puzzle *pz;
	int diff, ts;
#endif
	struct hip_r1entry *r1;
	HIP_R1E *entry;
	int idx;	

	idx = hip_calc_cookie_idx(ip_i, ip_r);
	_HIP_DEBUG("Calculated index: %d\n", idx);

	entry = hip_r1_find(hit);
	r1 = &(entry->r1table[idx]);
	/* the code under #if 0 periodically changes the puzzle. It is not included
	   in compilation as there is currently no easy way of signing the R1 packet
	   after having changed its puzzle.
	*/
#if 0
	/* generating opaque data */

	do_gettimeofday(&tv);

	/* extract the puzzle */
	pz = hip_get_param(r1->r1, HIP_PARAM_PUZZLE);
	if (!pz) {
		HIP_ERROR("Internal error: Could not find PUZZLE parameter in precreated R1 packet\n");
		return NULL;
	}

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
			return r1;
	}

	/* either ts == 0 or diff > HIP_PUZZLE_MAX_LIFETIME */
	_HIP_DEBUG("Creating new puzzle\n");
	hip_create_new_puzzle(pz, r1, &tv);

	/* XXX: sign the R1 */
#endif
	return r1;
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
	uint64_t digest;
	u8 cookie[48];
	struct scatterlist sg[2];
	unsigned int nsg = 2;
	int err;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	_HIP_DEBUG("\n");
	/* pre-create cookie */
	u = puzzle_or_solution;

	HIP_DEBUG("current hip_cookie_max_k_r1=%d\n",
		  hip_sys_config.hip_cookie_max_k_r1);
	if (u->pz.K > hip_sys_config.hip_cookie_max_k_r1) {
		HIP_ERROR("Cookie K %u is higher than we are willing to calculate"
			  " (current max K=%d)\n",
			  u->pz.K, hip_sys_config.hip_cookie_max_k_r1);
		return 0;
	}

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

	if (mode == HIP_VERIFY_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hits);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hitr);
		//randval = ntoh64(u->sl.J);
		randval = u->sl.J;
		_HIP_DEBUG("u->sl.J: 0x%llx\n", u->sl.J);
		maxtries = 1;
	} else if (mode == HIP_SOLVE_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hitr);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hits);
		maxtries = 1ULL << (u->pz.K + 2); /* fix */
		get_random_bytes(&randval, sizeof(u_int64_t));
	} else {
		HIP_ERROR("Unknown mode: %d\n", mode);
		goto out_err;
	}

	/* pre map the memory region (for SHA) */
	err = hip_map_virtual_to_pages(sg, &nsg, cookie, 48);
	if (err || nsg < 1 ) {
		HIP_ERROR("Error mapping virtual addresses to physical pages\n");
		return 0; // !ok
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
		hip_build_digest_repeat(impl_sha1, sg, nsg, sha_digest);
                /* copy the last 8 bytes for checking */
		memcpy(&digest, sha_digest + 12, 8);

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
		if (mode == HIP_VERIFY_PUZZLE) {
			HIP_ERROR("Puzzle incorrect\n");
			return 0;
		}
		randval++;
	}

 out_err:
	HIP_ERROR("Could not solve the puzzle, no solution found\n");
	return 0;
}


int hip_init_r1(void)
{
	/* XX TODO: some error handling..*/
	int res=0;
	
    	hip_init_r1db();
	
	res = 1;
	//err_out:
	return res;
}

int hip_precreate_r1(const struct in6_addr *src_hit)
{
	int i=0, err=0;
	HIP_R1E *entry;
	struct hip_common *pkt;

	entry = hip_allocate_r1db_entry();
	ipv6_addr_copy(&entry->hit, src_hit);

	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		pkt = hip_create_r1(src_hit);
		if (!pkt) {
			HIP_ERROR("Unable to precreate R1s\n");
			goto err_out;
		}
			
		entry->r1table[i].r1 = pkt; 
		
		HIP_DEBUG("Packet %d created\n",i);
	}
	err = hip_r1_insert(entry);

	return 1;

 err_out:
	//if (hip_r1table1) {
	//	hip_uninit_r1();
	//}
	return 0;
}

void hip_uninit_r1(void)
{
	//int i;
	
	/* XX TODO: do something;) */

	/* The R1 packet consist of 2 memory blocks. One contains the actual
	 * buffer where the packet is formed, while the other contains
	 * pointers to different TLVs to speed up parsing etc.
	 * The r1->common is the actual buffer, and r1 is the structure
	 * holding only pointers to the TLVs.
	 */
	/*if (hip_r1table1) {
	  for(i=0; i < HIP_R1TABLESIZE; i++) {
	  if (hip_r1table1[i].r1) {
	  kfree(hip_r1table1[i].r1);
	  }
	  }
	  kfree(hip_r1table1);
	  }*/
}


/**
 * hip_get_r1 - Fetch a precreated R1 and return it.
 * @ip_i: Initiator's IPv6 address
 * @ip_r: Responder's IPv6 address
 * 
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r, 
			      struct in6_addr *hit)
{
	struct hip_r1entry *r1e;

	r1e = hip_fetch_cookie_entry(ip_i, ip_r, hit);
	if (r1e == NULL)
		return NULL;

	return r1e->r1;
}

int hip_verify_generation(struct in6_addr *ip_i, struct in6_addr *ip_r,
			  uint64_t birthday, struct in6_addr *hit)
{
#if 0
	uint64_t generation;
#endif
	struct hip_r1entry *r1e;

	r1e = hip_fetch_cookie_entry(ip_i, ip_r, hit);
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
		      struct hip_solution *solution, 
		      struct in6_addr *hit)
{
	struct hip_puzzle *puzzle;
	struct hip_r1entry *result;
	int res;

	result = hip_fetch_cookie_entry(ip_i, ip_r, hit);
	if (result == NULL) {
		HIP_ERROR("No matching entry\n");
		return 0;
	}

	puzzle = hip_get_param(result->r1, HIP_PARAM_PUZZLE);
	if (!puzzle) {
		HIP_ERROR("Internal error: could not find the cookie\n");
		return 0;
	}

	_HIP_HEXDUMP("opaque in solution", solution->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in result", result->Copaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);

	if (memcmp(solution->opaque, puzzle->opaque,
		   HIP_PUZZLE_OPAQUE_LEN) != 0) {
		HIP_ERROR("Received cookie opaque does not match the sent opaque\n");
		return 0;
	}

	HIP_DEBUG("Solution's I (0x%llx), sent I (0x%llx)\n",
		  solution->I, puzzle->I);

	_HIP_HEXDUMP("opaque in solution", solution->opaque, 3);
	_HIP_HEXDUMP("opaque in result", result->Copaque, 3);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque, 3);

	if (solution->K != puzzle->K) {
		HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
			 solution->K, puzzle->K);

		if (solution->K != result->Ck) {
			HIP_ERROR("Solution's K did not match any sent Ks.\n");
			return 0;
		}

		if (solution->I != result->Ci) {
			HIP_ERROR("Solution's I did not match the sent I\n");
			return 0;
		}

		if (memcmp(solution->opaque, result->Copaque,
			   HIP_PUZZLE_OPAQUE_LEN) != 0) {
			HIP_ERROR("Solution's opaque data does not match sent opaque data\n");
			return 0;
		}

		HIP_DEBUG("Received solution to an old puzzle\n");

		res = hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE);
		if (!res)
			HIP_ERROR("Old puzzle incorrectly solved\n");
	} else {
		if (solution->I != puzzle->I) {
			HIP_ERROR("Solution's I did not match the sent I\n");
			return 0;
		}

		if (memcmp(solution->opaque, puzzle->opaque, 3) != 0) {
			HIP_ERROR("Solution's opaque data does not match the opaque data sent\n");
			return 0;
		}

		res = hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE);
		if (!res)
			HIP_ERROR("Puzzle incorrectly solved\n");
	}

	return res;
}


