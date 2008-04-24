/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "ife.h"
#include "midauth.h"
#include "misc.h"
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

	ipv6_addr_copy((struct in6_addr *)raw, a);
	ipv6_addr_copy((struct in6_addr *)(raw+16), b);
	memcpy(raw+32, &pisa_random_data[rnd][0], PISA_RANDOM_LEN);

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

	/* @todo FIXME BEGIN --- for testing purposes only */
	char *nonce1 = "asdfasdfasdf", *nonce2 = "01234567890123456789";
	midauth_add_echo_request_m(p, nonce1, strlen(nonce1));
	midauth_add_echo_request_m(p, nonce2, strlen(nonce2));
	/* @todo FIXME END --- for testing purposes only */

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
 * Check the validity of a PISA nonce. Check against current random value
 * first. If that fails, check against old random value. If that fails too, 
 * consider the nonce to be invalid (either too old or not correct at any 
 * previous point in time).
 *
 * @param p packet with the nonce to check
 * @return success (0) or failure
 */
static int pisa_check_nonce(struct midauth_packet *p)
{
	int err = 0;
	struct hip_tlv_common *nonce;
	u8 sha[2][HIP_AH_SHA_LEN], *nonce_data;
	int nonce_len;

	/* get the two values we will accept */
	pisa_create_nonce_hash(&p->hip->hitr, &p->hip->hits, 0, &sha[0][0]);
	pisa_create_nonce_hash(&p->hip->hitr, &p->hip->hits, 1, &sha[1][0]);

	nonce = hip_get_param(p->hip, HIP_PARAM_ECHO_RESPONSE_M);

	while (nonce) {
		/* loop over all HIP_PARAM_ECHO_RESPONSE_M */
		if (hip_get_param_type(nonce) != HIP_PARAM_ECHO_RESPONSE_M)
			break;

		nonce_len = hip_get_param_contents_len(nonce);
		nonce_data = (u8 *)hip_get_param_contents_direct(nonce);

		/* if the payload has the size of a SHA1 digest ... */
		if (nonce_len == HIP_AH_SHA_LEN) {
			/* ... first check the current random value ... */
			if (!memcmp(&sha[1][0], nonce_data, HIP_AH_SHA_LEN))
				return 0;
			/* ... and if that failed the old random value */
			if (!memcmp(&sha[0][0], nonce_data, HIP_AH_SHA_LEN))
				return 0;
		}

		nonce = hip_get_next_param(p->hip, (struct hip_tlv_common *)nonce);
	}

	return -1;
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

	HIP_IFEL(midauth_verify_solution_m(p->hip, solution), -1, "PISA solution was wrong.");

	HIP_DEBUG("PISA solution was correct.\n");

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
	if (pisa_check_nonce(p) == 0)
		HIP_DEBUG("A PISA nonce was accepted.\n");
	else
		HIP_DEBUG("No PISA nonce was accepted.\n");

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

