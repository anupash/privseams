/*
 * HIP cookie handling
 * 
 * Authors: Kristian Slavov <ksl@iki.fi>
 *          Miika Komu <miika@iki.fi>
 *
 */

#include "cookie.h"

struct hip_r1entry *hip_r1table;

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

static struct hip_r1entry *hip_fetch_cookie_entry(struct in6_addr *ip_i,
						  struct in6_addr *ip_r)
{
	int idx;

	idx = hip_calc_cookie_idx(ip_i, ip_r);

	HIP_DEBUG("Calculated index: %d\n", idx);

	return &hip_r1table[idx];
}


/**
 * hip_solve_puzzle - Solve puzzle.
 * @puzzle: the puzzle
 * @hdr: The incoming R1/I2 packet header.
 * @param: Pointer to 64-bit value, that is used according to the mode.
 *         The value is interpreted as beeing in network byte order.
 * @mode: Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * If @mode is %HIP_VERIFY_PUZZLE, then @param is the difficulty factor.
 * In @mode %HIP_SOLVE_PUZZLE, the @param variable is used as
 * call-by-value-result argument. After the call the @param contains the
 * value that solves the puzzle.
 *
 * When verifying the puzzle, the puzzle argument must consist of
 * the J value, that supposedly solves the puzzle.
 *
 * Returns: 1 if success (= ?), otherwise 0
 */
int hip_solve_puzzle(struct hip_birthday_cookie *puzzle, 
		     struct hip_common *hdr, uint64_t *param, int mode)
{
	uint64_t rand_jk;
	uint64_t mask;
	uint64_t randval;
	uint64_t maxtries;
	uint64_t digest;
	u8 cookie[48];
	int bit = 0;
	struct scatterlist sg[2];
	unsigned int nsg = 2;
	int err;

	/* pre-create cookie */
	HIP_DEBUG("Received I=%llx\n", puzzle->val_i);

	memcpy(cookie,(u8 *)&puzzle->val_i, sizeof(uint64_t)); // 8

	if (mode == HIP_VERIFY_PUZZLE) 
	{
		memcpy(cookie + 8, &hdr->hits, sizeof(struct in6_addr));
		memcpy(cookie + 24, &hdr->hitr, sizeof(struct in6_addr));
		randval = puzzle->val_jk;
		mask = hton64(*param == 64ULL ? 0xffffffffffffffffULL : (1ULL << * param) - 1);
		maxtries = 1;
	} 
	else if (mode == HIP_SOLVE_PUZZLE)
	{
		rand_jk = ntoh64(puzzle->val_jk);
		if (rand_jk > 64) 
		{
			HIP_ERROR("Puzzle difficulty factor too large! (%lld)\n",rand_jk);
			goto out_err;
		}

		mask = hton64(rand_jk == 64ULL ? 0xffffffffffffffffULL: (1ULL << rand_jk)-1);
		memcpy(cookie + 8, &hdr->hitr, sizeof(struct in6_addr)); // 16
		memcpy(cookie + 24, &hdr->hits, sizeof(struct in6_addr)); // 16

		HIP_HEXDUMP("cookie buffer", cookie, 40);
		get_random_bytes(&randval,sizeof(u_int64_t));
		if (rand_jk + 2 >= 64)
			maxtries = 0xffffffffffffffffULL;
		else
			maxtries = (1ULL << (rand_jk + 2));
	}
	else
	{
		HIP_ERROR("Unknown mode: %x\n",mode);
		goto out_err;
	}

	/* pre map the memory region (for SHA) */
	err = hip_map_virtual_to_pages(sg, &nsg, cookie, 48);
	if (err || nsg < 1 ) {
		HIP_ERROR("Error mapping virtual addresses to physical pages\n");
		return 0; // !ok
	}
	


	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]... 
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0)
	{
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
			HIP_DEBUG("*** Puzzle solved ***: %llx\n",randval);
			bit = 1;
			if (mode == HIP_SOLVE_PUZZLE)
#if 0
				*param = hton64(randval);
#endif
				*param = (randval);
			break;
		}

		/* It seems like the puzzle was not correctly solved */
		if (mode == HIP_VERIFY_PUZZLE)
		{
			HIP_ERROR("Puzzle incorrect\n");
			return 0;
		}

		randval++;
	}
		
	if (bit == 0)
	{
		HIP_ERROR("Could not solve the puzzle\n");
		return 0;
	}
	
	return 1; /*ok*/
 out_err:
	return 0;
}



int hip_init_r1(void)
{
	int res=0;

	hip_r1table = kmalloc(sizeof(struct hip_r1entry) * HIP_R1TABLESIZE,
			      GFP_KERNEL);
	if (!hip_r1table) {
		HIP_ERROR("Could not allocate memory for R1 table\n");
		goto err_out;
	}

	memset(hip_r1table, 0, sizeof(struct hip_r1entry) * HIP_R1TABLESIZE);
	res = 1;
 err_out:
	return res;
}

int hip_precreate_r1(struct in6_addr *src_hit)
{
	int i=0;
	struct hip_common *pkt;

	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		pkt = hip_create_r1(src_hit);
		if (!pkt) {
			HIP_ERROR("Unable to precreate R1s\n");
			goto err_out;
		}
		hip_r1table[i].r1 = pkt;
		HIP_DEBUG("Packet %d created\n",i);
	}

	return 1;

 err_out:
	if (hip_r1table) {
		hip_uninit_r1();
		hip_r1table = NULL;
	}
	return 0;
}

void hip_uninit_r1(void)
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
				kfree(hip_r1table[i].r1);
			}
		}
		kfree(hip_r1table);
	}
}


struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r)
{
	struct hip_r1entry *r1e;

	r1e = hip_fetch_cookie_entry(ip_i, ip_r);
	if (r1e == NULL)
		return NULL;

	/* lock r1e */
	r1e->used++;
	/* unlock r1e */

	return r1e->r1;
}



int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr,
		      struct hip_birthday_cookie *cookie)
{
	struct hip_birthday_cookie *oldcookie;
	struct hip_r1entry *result;
	int res;

	result = hip_fetch_cookie_entry(ip_i, ip_r);
	if (result == NULL) {
		HIP_ERROR("No matching entry\n");
		return 0;
	}

	oldcookie = hip_get_param(result->r1, HIP_PARAM_BIRTHDAY_COOKIE_R1);
	if (!oldcookie) {
		HIP_ERROR("Internal error: could not find the cookie\n");
		return 0;
	}

	if (cookie->val_i == oldcookie->val_i) {
		res = hip_solve_puzzle(cookie, hdr, &oldcookie->val_jk,
				       HIP_VERIFY_PUZZLE);
		if (!res)
			HIP_ERROR("Puzzle incorrectly solved\n");

	} else 	if (cookie->val_i == result->Ci) {
		res = hip_solve_puzzle(cookie,hdr, &result->Ck,
				       HIP_VERIFY_PUZZLE);
		if (!res)
			HIP_ERROR("Old puzzle incorrectly solved\n");

	} else {
		HIP_ERROR("WARNING: Unknown cookie\n");
		return 0;
	}
	return res;
}
