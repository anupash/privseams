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
#define PISA_PUZZLE_SEED 0xDEADC0DE
#define PISA_NONCE_LEN (4 + HIP_AH_SHA_LEN)

/*#define PISA_TEST_MULTIPLE_PARAMETERS*/
/*#define PISA_INTRODUCE_ERROR_NONCE*/
/*#define PISA_INTRODUCE_ERROR_PUZZLE_OPAQUE*/
/*#define PISA_INTRODUCE_ERROR_PUZZLE_RANDOM*/

struct pisa_puzzle_hash {
	u8 data[4];
	union {
		u8 raw[HIP_AH_SHA_LEN];
		struct {
			uint64_t random;
			u8 opaque[6];
		} pz;
	} u;
};

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
 * Appends HMAC/SHA1 to a block of data.
 *
 * @param a first HIT
 * @param b second HIT
 * @param rnd which random number to use, either 0 or 1
 * @param spi SPI of that will be signed
 * @param data pointer to buffer for data and the HMAC
 */
static void pisa_append_hmac(struct in6_addr *a, struct in6_addr *b, 
                                   int rnd, u32 spi, void *data, int data_len)
{
	u8 key[36 + PISA_RANDOM_LEN];
	int len = HIP_AH_SHA_LEN;

	if (!(data && a && b) || (rnd != 0 && rnd != 1) || data_len == 0)  {
		HIP_ERROR("failed pisa_create_nonce_hash sanity check.\n");
		return;
	}

	/* The key for HMAC/SHA1 consists of:
	 *    4 bytes SPI
	 *   16 bytes HIT1
	 *   16 bytes HIT2
	 *            pisa_random_data
	 */

	memcpy(key, &spi, sizeof(u32));
	ipv6_addr_copy((struct in6_addr *)(key+ 4), a);
	ipv6_addr_copy((struct in6_addr *)(key+20), b);
	memcpy(key+36, &pisa_random_data[rnd][0], PISA_RANDOM_LEN);

	HMAC(EVP_sha1(), key, 36 + PISA_RANDOM_LEN, data, data_len, data + data_len, &len);
}

/**
 * Insert a PISA nonce into a packet.
 *
 * @param ctx context of the packet where the nonce will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_nonce(hip_fw_context_t *ctx)
{
	u8 nonce[PISA_NONCE_LEN];
	struct hip_esp_info *esp_info;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u32 spi;

	esp_info = hip_get_param(hip, HIP_PARAM_ESP_INFO);
	spi = esp_info->new_spi;

#ifdef PISA_TEST_MULTIPLE_PARAMETERS
	{
		char *nonce1 = "asdf", *nonce2 = "012345678901234567890123";
		midauth_add_echo_request_m(ctx, nonce1, strlen(nonce1));
		midauth_add_echo_request_m(ctx, nonce2, strlen(nonce2));
	}
#endif
	/* The nonce looks like this:
	 *    4 bytes SPI
	 *   20 bytes HMAC of everything before
	 * As we only use the data in the firewall, byteorder is not an issue.
	 */

	memcpy(nonce, &spi, sizeof(u32));
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, spi, nonce, 4);

#ifdef PISA_INTRODUCE_ERROR_NONCE
	nonce[0]++;
#endif

	return midauth_add_echo_request_m(ctx, nonce, PISA_NONCE_LEN);
}

/**
 * Insert a PISA puzzle into a packet.
 *
 * @param ctx context of the packet where the puzzle will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_puzzle(hip_fw_context_t *ctx)
{
	struct pisa_puzzle_hash hash;
	struct hip_common *hip = ctx->transport_hdr.hip;
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash, &seed, 4);

	/* here we switch order of initiator and receiver to obtain an other
	 * SHA1 hash */
	pisa_append_hmac(&hip->hitr, &hip->hits, 1, 0, &hash, 4);

#ifdef PISA_TEST_MULTIPLE_PARAMETERS
	midauth_add_puzzle_m(ctx, 3, 4, "puzzle", 0xABCDABCDABCDABCDLL);
	midauth_add_puzzle_m(ctx, 3, 4, "abcdef", 0x0123456789ABCDEFLL);
#endif

#ifdef PISA_INTRODUCE_ERROR_PUZZLE_OPAQUE
	hash.u.pz.opaque[0]++;
#endif

#ifdef PISA_INTRODUCE_ERROR_PUZZLE_RANDOM
	hash.u.pz.random++;
#endif

	return midauth_add_puzzle_m(ctx, 3, 4, hash.u.pz.opaque, hash.u.pz.random);
}

/**
 * Check the validity of a PISA nonce. Check against current random value
 * first. If that fails, check against old random value. If that fails too, 
 * consider the nonce to be invalid (either too old or not correct at any 
 * previous point in time).
 *
 * @param ctx context of the packet with the nonce to check
 * @return success (0) or failure
 */
static int pisa_check_nonce(hip_fw_context_t *ctx)
{
	struct hip_tlv_common *nonce;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u8 valid[PISA_NONCE_LEN], *nonce_data;
	u32 spi;
	int nonce_len;

	nonce = hip_get_param(hip, HIP_PARAM_ECHO_RESPONSE_M);

	while (nonce) {
		/* loop over all HIP_PARAM_ECHO_RESPONSE_M */
		if (hip_get_param_type(nonce) != HIP_PARAM_ECHO_RESPONSE_M)
			break;

		nonce_len = hip_get_param_contents_len(nonce);
		nonce_data = (u8 *)hip_get_param_contents_direct(nonce);

		/* if the payload has the size of a nonce ... */
		if (nonce_len == PISA_NONCE_LEN) {
			memcpy(valid, nonce_data, 4);
			spi = *((u32 *)nonce_data);

			/* ... first check the current random value ... */
			pisa_append_hmac(&hip->hitr, &hip->hits, 1, spi, valid, 4);
			if (!memcmp(valid, nonce_data, PISA_NONCE_LEN))
				return 0;

			/* ... and if that failed the old random value */
			pisa_append_hmac(&hip->hitr, &hip->hits, 0, spi, valid, 4);
			if (!memcmp(valid, nonce_data, PISA_NONCE_LEN))
				return 0;
		}

		nonce = hip_get_next_param(hip, nonce);
	}

	return -1;
}

/**
 * Check the validity of a PISA puzzle. 
 *
 * @param ctx context of the packet with the puzzle to check
 * @return success (0) or failure
 */
static int pisa_check_solution(hip_fw_context_t *ctx)
{
	struct hip_solution_m *solution;
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct pisa_puzzle_hash hash[2];
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash[0], &seed, 4);
	memcpy(&hash[1], &seed, 4);

	pisa_append_hmac(&hip->hits, &hip->hitr, 0, 0, &hash[0], 4);
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, 0, &hash[1], 4);

	solution = (struct hip_solution_m *)
	           hip_get_param(hip, HIP_PARAM_SOLUTION_M);

	while (solution) {
		/* loop over all HIP_PARAM_SOLUTION_M */
		if (hip_get_param_type(solution) != HIP_PARAM_SOLUTION_M)
			break;

		if ((!memcmp(solution->opaque, hash[1].u.pz.opaque, 6)
		      && solution->I == hash[1].u.pz.random) ||
		    (!memcmp(solution->opaque, hash[0].u.pz.opaque, 6)
		      && solution->I == hash[0].u.pz.random)) {
			if (midauth_verify_solution_m(hip, solution) == 0)
				return 0;
		}

		solution = (struct hip_solution_m *) hip_get_next_param(hip, 
		             (struct hip_tlv_common *) solution);
	}

	return -1;
}

/**
 * Check the signature of the packet.
 *
 * @param ctx context of the packet with the signature to check
 * @return success (0) or failure
 */
static int pisa_check_signature(hip_fw_context_t *ctx)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	int err = -1;
	struct hip_host_id *host_id;
	int (*verify_signature)(struct hip_host_id *, struct hip_common *);

	host_id = hip_get_param(hip, HIP_PARAM_HOST_ID);
	if (host_id == 0) {
		HIP_DEBUG("Cannot check signature: No HOST_ID found.\n");
	} else {
	verify_signature = (hip_get_host_id_algo(host_id) == HIP_HI_RSA ?
	                    hip_rsa_verify : hip_dsa_verify);

	err = verify_signature(host_id, hip);
	}

out_err:
	return err;
}

/**
 * Accept a connection via PISA. Update firewall to allow further packages to
 * pass through.
 *
 * @param ctx context of the packet that belongs to that connection
 */
static void pisa_accept_connection(hip_fw_context_t *ctx)
{
	/* @todo: FIXME - implement this stub */
	HIP_INFO("PISA accepted the connection.\n");
}

/**
 * Reject a connection via PISA. Update firewall to allow no further packages
 * to pass through.
 *
 * @param ctx context of the packet that belongs to that connection
 */
static void pisa_reject_connection(hip_fw_context_t *ctx)
{
	/* @todo: FIXME - implement this stub */
	HIP_INFO("PISA rejected the connection.\n");
}

/**
 * Insert a PISA nonce and a PISA puzzle into the packet.
 *
 * @param ctx context of the packet to modify
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_i2(hip_fw_context_t *ctx)
{
	int verdict = NF_ACCEPT;

	pisa_insert_nonce(ctx);
	pisa_insert_puzzle(ctx);

	return verdict;
}

/**
 * Check for a PISA nonce and a PISA puzzle in the packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_r2(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, nonce = 0, solution = 0, sig = 0;

	nonce = pisa_check_nonce(ctx);
	solution = pisa_check_solution(ctx);
	sig = pisa_check_signature(ctx);

	if (nonce != 0 || solution != 0 || sig != 0) {
		/* disallow further communication if either nonce or solution
		 * were not correct */
		pisa_reject_connection(ctx);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection(ctx);
		verdict = NF_ACCEPT;
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
	h->u2 = pisa_handler_i2;
	h->u3 = pisa_handler_r2;

	pisa_generate_random();
	pisa_generate_random();
}

#endif

