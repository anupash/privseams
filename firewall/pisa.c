/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "ife.h"
#include "midauth.h"
#include "pisa.h"
#include <string.h>

#define PISA_RANDOM_LEN 16

static char pisa_random_data[2][PISA_RANDOM_LEN];

/**
 * Generate a new random number and shift the old one down.
 */
static void pisa_generate_random()
{
	memcpy(&pisa_random_data[0][0], &pisa_random_data[1][0], PISA_RANDOM_LEN);
	get_random_bytes(&pisa_random_data[1][0], PISA_RANDOM_LEN);
}

/**
 * Compute a PISA nonce and place it in preallocated buffer. A PISA nonce is a
 * SHA1 digest of the concatenation of initiator HIT, responder HIT and the
 * current random number.
 *
 * @param a first HIT
 * @param b second HIT
 * @param rnd which random number to use, either 0 or 1
 * @param digest pointer to buffer for the nonce, needs HIP_AH_SHA_LEN bytes
 */
static void pisa_create_nonce_hash(struct in6_addr *a, struct in6_addr *b, 
                                   int rnd, u8 *digest)
{
	u8 raw[32 + PISA_RANDOM_LEN];

	if (!(digest && a && b) || (rnd != 0 && rnd != 1))  {
		HIP_ERROR("failed pisa_create_nonce_hash sanity check.\n");
		return;
	}

	memcpy(raw, a, 16);
	memcpy(raw+16, b, 16);
	/* @todo FIXME: use this function?
	 * ipv6_addr_copy((hip_hit_t *)(raw+16), &p->hip->hits);
	 */
	memcpy(raw+32, &pisa_random_data[rnd][0], 
	       PISA_RANDOM_LEN);

	hip_build_digest(HIP_DIGEST_SHA1, raw, 32 + PISA_RANDOM_LEN, digest);
}

/**
 * Insert a PISA nonce into a packet.
 *
 * @param p packet where the nonce will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_nonce(struct midauth_packet *p)
{
	u8 sha[HIP_AH_SHA_LEN];

	pisa_create_nonce_hash(&p->hip->hits, &p->hip->hitr, 1, sha);
	return midauth_add_echo_request_m(p, sha, HIP_AH_SHA_LEN);
}

/**
 * Insert a PISA puzzle into a packet.
 *
 * @param p packet where the puzzle will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_puzzle(struct midauth_packet *p)
{
	int err = 0;

	err = midauth_add_puzzle_m(p, 3, 4, "puzzle", 0xABCDABCDABCDABCDLL);
out_err:
	return err;
}

/**
 * Check the validity of a PISA nonce. Check against current random value, if
 * that fails, check against old random value. If that fails too, consider the
 * nonce to be invalid.
 *
 * @param p packet with the nonce to check
 * @return success (0) or failure
 */
static int pisa_check_nonce(struct midauth_packet *p)
{
	int err = 0;
	struct hip_echo_response_m *nonce;
	u8 sha[HIP_AH_SHA_LEN], *nonce_data;
	int nonce_len;

	/* @todo find our nonce out of multiple items */

	nonce = (struct hip_echo_response_m *)
	        hip_get_param(p->hip, HIP_PARAM_ECHO_RESPONSE_M);

	HIP_IFEL(!nonce, -1, "No PISA nonce found.\n");

	nonce_len = hip_get_param_contents_len(nonce);
	nonce_data = (u8 *)hip_get_param_contents_direct(nonce);

	HIP_IFEL(nonce_len != HIP_AH_SHA_LEN, -1, 
	        "PISA nonce had size %d, expected %d.\n", nonce_len,
	        HIP_AH_SHA_LEN);

	/* first check the current random value ... */
	pisa_create_nonce_hash(&p->hip->hitr, &p->hip->hits, 1, sha);
	if (!memcmp(sha, nonce_data, HIP_AH_SHA_LEN)) {
		HIP_DEBUG("PISA nonce was correct.\n");
	} else {
		/* ... and if that failed the old random value ... */
		pisa_create_nonce_hash(&p->hip->hitr, &p->hip->hits, 0, sha);
		if (!memcmp(sha, nonce_data, HIP_AH_SHA_LEN)) {
			HIP_DEBUG("PISA nonce was correct.\n");
		} else {
			/* ... if that fails too, you were too slow */
			HIP_ERROR("PISA nonce was wrong (perhaps too old).\n");
			err = -1;
		}
	}

out_err:
	return err;
}

/**
 * Check the validity of a PISA puzzle. 
 *
 * @param p packet with the puzzle to check
 * @return success (0) or failure
 */
static int pisa_check_solution(struct midauth_packet *p)
{
	int err = 0;
	struct hip_solution_m *solution;

	/* @todo find our solution out of multiple items */

	solution = (struct hip_solution_m *)
	           hip_get_param(p->hip, HIP_PARAM_SOLUTION_M);

	HIP_IFEL(!solution, -1, "No PISA solution found.\n");

	HIP_IFEL(midauth_verify_solution_m(p->hip, solution), -1, "PISA solution was wrong");

	HIP_DEBUG("PISA solution was correct\n");

out_err:
	return err;
}

int pisa_handler_i2(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;

	pisa_insert_nonce(p);
	pisa_insert_puzzle(p);

	return verdict;
}

int pisa_handler_r2(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	pisa_check_solution(p);
	pisa_check_nonce(p);

	return verdict;
}

void pisa_init(struct midauth_handlers *h)
{
	h->i1 = midauth_handler_accept;
	h->r1 = midauth_handler_accept;
	h->i2 = pisa_handler_i2;
	h->r2 = pisa_handler_r2;
	h->u1 = midauth_handler_accept;
	h->u2 = midauth_handler_accept;
	h->u3 = midauth_handler_accept;

	pisa_generate_random();
	pisa_generate_random();
}

#endif

