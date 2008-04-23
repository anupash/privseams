/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

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
 * Insert a PISA nonce into a packet.
 *
 * @param p packet where the nonce will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_nonce(struct midauth_packet *p)
{
	int err = 0;
	u8 sha[HIP_AH_SHA_LEN], raw[32 + PISA_RANDOM_LEN];

	/* A nonce is a SHA1 digest of the following information:
	 *   - sender HIT
	 *   - receiver HIT
	 *   - newest random number
	 */

	memcpy(raw, &p->hip->hits, 16);
	memcpy(raw+16, &p->hip->hitr, 16); /* @todo FIXME */
	memcpy(raw+32, &pisa_random_data[1][0], PISA_RANDOM_LEN);

	hip_build_digest(HIP_DIGEST_SHA1, raw, 32 + PISA_RANDOM_LEN, sha);

	err = midauth_add_echo_request_m(p, sha, HIP_AH_SHA_LEN);
out_err:
	return err;
}

/**
 * Insert a PISA puzzle into a packet
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
	struct hip_solution_m *solution;
	struct hip_echo_response_m *nonce;

	/* check for ECHO_REPLY_M and SOLUTION_M here */
	solution = (struct hip_solution_m *)hip_get_param(p->hip, HIP_PARAM_SOLUTION_M);
	if (solution)
	{
		if (midauth_verify_solution_m(p->hip, solution) == 0)
			HIP_DEBUG("found correct hip_solution_m\n");
		else
			HIP_DEBUG("found wrong hip_solution_m\n");
	} else {
		HIP_DEBUG("found no hip_solution_m\n");
	}

	nonce = (struct hip_echo_response_m *)hip_get_param(p->hip, HIP_PARAM_ECHO_RESPONSE_M);

	if (nonce) {
		u8 sha[HIP_AH_SHA_LEN], raw[32 + PISA_RANDOM_LEN], *nonce_data;
		int nonce_len;

		memcpy(raw, &p->hip->hitr, 16);
		memcpy(raw+16, &p->hip->hits, 16);
		/*ipv6_addr_copy((hip_hit_t *)(raw+16), &p->hip->hits); @todo
 * FIXME*/
		memcpy(raw+32, &pisa_random_data[1][0], PISA_RANDOM_LEN);

		hip_build_digest(HIP_DIGEST_SHA1, raw, 32 + PISA_RANDOM_LEN, sha);

		nonce_len = hip_get_param_contents_len(nonce);
		nonce_data = (u8 *)hip_get_param_contents_direct(nonce);

		if (nonce_len != HIP_AH_SHA_LEN) {
			HIP_ERROR("nonce had length %d, expected %d\n", nonce_len, 32 + PISA_RANDOM_LEN);
			return -1;
		}

		if (!memcmp(sha, nonce_data, HIP_AH_SHA_LEN)) {
			HIP_DEBUG("nonce was correct\n");
		} else {
			HIP_DEBUG("nonce was there, but wrong\n");
		}
	} else {
		HIP_DEBUG("no nonce found\n");
	}

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

