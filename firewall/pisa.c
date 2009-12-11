/** @file
 * This file contains PISA specific functions for the firewall. The basic idea
 * is to modify the HIP messages and manage state for allowed connections to
 * allow or reject associated ESP traffic.
 *
 * @author Thomas Jansen
 * @author Dominic Gatzen
 *
 * This code is GNU/GPL.
 */

#include "ife.h"
#include "midauth.h"
#include "misc.h"
#include "pisa.h"
#include "pisa_cert.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

#define PISA_RANDOM_LEN 16
#define PISA_PUZZLE_SEED 0xDEADC0DE
#define PISA_PUZZLE_OPAQUE_LEN (4 + HIP_AH_SHA_LEN)

/* pisa_check_for_random_update is called at least every PISA_RANDOM_TTL
 * seconds. Worst case timer resolution depends on the timeout in the select
 * call */
#define PISA_RANDOM_TTL 2.0

#ifdef CONFIG_HIP_PERFORMANCE
#include "performance.h"
#endif

struct tuple * get_tuple_by_hits(const struct in6_addr *src_hit,
				 const struct in6_addr *dst_hit);


static char pisa_random_data[2][PISA_RANDOM_LEN];
static struct in6_addr community_operator_hit;

/* @todo make this configurable, issuer HIT */
#define CO_HIT "2001:001a:b1b0:0aad:0f92:15ca:280c:9430"
#define CO_HIT_FILE "/etc/hip/co_hit"

/**
 * Generate a new random number and shift the old one down.
 */
static void pisa_generate_random()
{
	void *p0, *p1;

	p0 = &pisa_random_data[0][0];
	p1 = &pisa_random_data[1][0];

	memcpy(p0, p1, PISA_RANDOM_LEN);
	get_random_bytes(p1, PISA_RANDOM_LEN);
}

/**
 * Reads out the HIT of the Community-Operator 
 * from file CO_HIT_FILE
 * @param hit A pointer to the char where the HIT should be stored
 * @return 1-> success
 * @return 0-> error
 */
static int pisa_read_communit_operator_hit(char *hit)
{
	FILE *f;
	char *eofline;

	f = fopen(CO_HIT_FILE,"r");
	
	if(f==NULL)
		return 0;

	fgets(hit,INET6_ADDRSTRLEN,f);
	eofline = strchr(hit, '\n');
	if (eofline)
		*eofline = '\0';

	fclose(f);

	return 1;
}


void pisa_check_for_random_update()
{
	static time_t lastupdate = 0;
	time_t now;

	time(&now);
	if (difftime(now, lastupdate) > PISA_RANDOM_TTL) {
		pisa_generate_random();
		lastupdate = now;
	}
}

/**
 * Appends HMAC/SHA1 to a block of data.
 *
 * @param hit1 first HIT
 * @param hit2 second HIT
 * @param rnd which random number to use, either 0 or 1
 * @param data pointer to buffer for data and the HMAC
 * @param data_len length of data
 * @return 0 on success
 */
static int pisa_append_hmac(struct in6_addr *hit1, struct in6_addr *hit2,
			    int rnd, void *data, int data_len)
{
	u8 key[32 + PISA_RANDOM_LEN];
	int err = 0;
	unsigned int len = HIP_AH_SHA_LEN;

	/* sanity checks for arguments */
	HIP_IFEL(data == NULL, -1, "No data given.\n");
	HIP_IFEL(hit1 == NULL, -1, "No first HIT given.\n");
	HIP_IFEL(hit2 == NULL, -1, "No second HIT given.\n");
	HIP_IFEL(data_len < 1, -1, "Data has invalid length.\n");
	HIP_IFEL(rnd != 0 && rnd != 1, -1, "Random ID is neither 0 nor 1.\n");

	/* The key for HMAC/SHA1 consists of:
	 *                16 bytes HIT1
	 *                16 bytes HIT2
	 *   PISA_RANDOM_LEN bytes pisa_random_data
	 */

	ipv6_addr_copy((struct in6_addr *)(key+ 0), hit1);
	ipv6_addr_copy((struct in6_addr *)(key+16), hit2);
	memcpy(key+32, &pisa_random_data[rnd][0], PISA_RANDOM_LEN);

	HMAC(EVP_sha1(), key, 32 + PISA_RANDOM_LEN, data, data_len,
	     data + data_len, &len);

out_err:
	return err;
}


/**
 * Insert a PISA puzzle into a packet.
 *
 * @param ctx context of the packet where the puzzle will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_puzzle(hip_fw_context_t *ctx)
{

	uint8_t opaque[PISA_PUZZLE_OPAQUE_LEN];

	struct hip_common *hip = ctx->transport_hdr.hip;
	int seed = PISA_PUZZLE_SEED;

	memcpy(&opaque, &seed, 4);

	/* here we switch order of initiator and receiver to obtain a
	 * different SHA1 hash */
	pisa_append_hmac(&hip->hitr, &hip->hits, 1, &opaque, 4);

	return midauth_add_challenge_request(ctx, 3, 4, opaque,PISA_PUZZLE_OPAQUE_LEN);
}


/**
 * Check the validity of a PISA challenge_response.
 *
 * @param ctx context of the packet with the puzzle to check
 * @return pointer to the puzzle we accepted or NULL at failure
 */
static struct hip_challenge_response *pisa_check_challenge_response(hip_fw_context_t *ctx)
{
	struct hip_challenge_response *response;
	struct hip_common *hip = ctx->transport_hdr.hip;
	uint8_t hash[2][PISA_PUZZLE_OPAQUE_LEN];
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash[0][0], &seed, 4);
	memcpy(&hash[1][0], &seed, 4);

	pisa_append_hmac(&hip->hits, &hip->hitr, 0, &hash[0], 4);
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, &hash[1], 4);

	response =  hip_get_param(hip, HIP_PARAM_CHALLENGE_RESPONSE);

	while (response) {
		/* loop over all HIP_PARAM_CHALLENGE_RESPONSE */
		if (hip_get_param_type(response) != HIP_PARAM_CHALLENGE_RESPONSE)
			break;
		if ((!memcmp(response->opaque, &hash[1][0], PISA_PUZZLE_OPAQUE_LEN)) ||
		    (!memcmp(response->opaque, &hash[0][0], PISA_PUZZLE_OPAQUE_LEN))) {
			if (midauth_verify_challenge_response(hip, response) == 0)
				return response;
		}

		response = (struct hip_challenge_response *) hip_get_next_param(hip,
				(struct hip_tlv_common *) response);
	}

	return NULL;
}

/**
 * Check the signature of the packet.
 *
 * @param ctx context of the packet with the signature to check
 * @return success (0) or failure
 */
/* This function is not used */
#if 0
static int pisa_check_signature(hip_fw_context_t *ctx)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	int err = -1;
	struct hip_host_id *host_id;

	host_id = hip_get_param(hip, HIP_PARAM_HOST_ID);
	HIP_IFEL (host_id == 0, -1, "Cannot check signature: No HOST_ID found.\n");

	if (hip_get_host_id_algo(host_id) == HIP_HI_RSA) {
		RSA *rsa;
		rsa = hip_key_rr_to_rsa(host_id, 0);
		err = hip_rsa_verify(rsa, hip);
		RSA_free(rsa);
	} else {
		DSA *dsa;
		dsa = hip_key_rr_to_dsa(host_id, 0);
		err = hip_dsa_verify(dsa, hip);
		DSA_free(dsa);
	}

out_err:
	return err;
}
#endif /* 0 */

/**
 * Check the certificate of the packet.
 *
 * @param ctx context of the packet with the certificate to check
 * @return success (0) or failure
 */
static int pisa_check_certificate(hip_fw_context_t *ctx)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct hip_cert *cert;
	struct hip_cert_spki_info ci;
	struct pisa_cert pc;
	char *buf = NULL;
	int err = 0, len;
	time_t now = time(NULL);

	cert = hip_get_param(hip, HIP_PARAM_CERT);
	HIP_IFEL(cert == NULL, -1, "No certificate found.\n");

	len = ntohs(cert->length);
	buf = malloc(len);
	memset(buf, 0, len + 1);
	memcpy(buf, cert + 1, len);

	HIP_IFEL(hip_cert_spki_char2certinfo(buf, &ci), -1,
		 "Certificate could not be parsed.\n");
	HIP_IFEL(hip_cert_spki_lib_verify(&ci), -1,
		 "Certificate could not be verified.\n");

	pisa_split_cert(ci.cert, &pc);

	/* Three conditions must be fulfilled for a certificate to be valid:
	 *
	 *  - The current time on the middlebox must be in the before/after
	 *    interval
	 *  - The certificate must be issued by the community operator (i.e.
	 *    the CO HIT must be used by the issuer)
	 *  - The host sending the certificate must be the one mentioned in
	 *    the certificate
	 */
	HIP_IFEL(now < pc.not_before, -1,
		 "Certificate is not valid yet.\n");
	HIP_IFEL(now > pc.not_after, -1,
		 "Certificate has expired.\n");

	
	HIP_IFEL(ipv6_addr_cmp(&pc.hit_issuer, &community_operator_hit) != 0,
		 -1, "Certificate not issued by the community operator.\n");
#if 0
	HIP_IFEL(ipv6_addr_cmp(&pc.hit_subject, &hip->hits) != 0, -1,
		 "Certificate does not belong to subject.\n");
#endif

	HIP_INFO("Certificate successfully verified.\n");

out_err:
	if (buf)
		free(buf);
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
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct tuple *t = get_tuple_by_hits(&hip->hits, &hip->hitr);

	if (t) {
		t->connection->pisa_state = PISA_STATE_ALLOW;
		HIP_INFO("PISA accepted the connection.\n");
	} else {
		HIP_ERROR("Connection not found.\n");
	}
}


/**
 * Remove a connection from the list of accepted connections based on the hits
 * of a packet.
 *
 * @param ctx context of the packet that contains HITs of the connection
 */
static void pisa_remove_connection(hip_fw_context_t *ctx)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct tuple *t = get_tuple_by_hits(&hip->hits, &hip->hitr);

	if (t) {
		t->connection->pisa_state = PISA_STATE_DISALLOW;
	}
}

/**
 * Reject a connection via PISA. Update firewall to allow no further packages
 * to pass through.
 *
 * @param ctx context of the packet that belongs to that connection
 */
static void pisa_reject_connection(hip_fw_context_t *ctx)
{
	HIP_INFO("PISA rejected the connection.\n");
	pisa_remove_connection(ctx);
}

/**
 * Dummy function, necessary only for performance measurements.
 *
 * @param ctx context of the packet containing the I1
 * @return NF_ACCEPT verdict
 */
static int pisa_handler_i1(hip_fw_context_t *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_BASE, PERF_I1\n");
	hip_perf_start_benchmark(perf_set, PERF_BASE);
	hip_perf_start_benchmark(perf_set, PERF_I1);
#endif

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_I1\n");
	hip_perf_stop_benchmark(perf_set, PERF_I1);
	hip_perf_write_benchmark(perf_set, PERF_I1);
#endif

	return NF_ACCEPT;
}

/**
 * Dummy function, necessary only for performance measurements.
 *
 * @param ctx context of the packet containing the R1
 * @return NF_ACCEPT verdict
 */
static int pisa_handler_r1(hip_fw_context_t *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_R1\n");
	hip_perf_start_benchmark(perf_set, PERF_R1);
#endif

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_R1\n");
	hip_perf_stop_benchmark(perf_set, PERF_R1);
	hip_perf_write_benchmark(perf_set, PERF_R1);
#endif

	return NF_ACCEPT;
}

/**
 * Insert a PISA puzzle into the I2 packet.
 *
 * @param ctx context of the packet to modify
 * @return NF_ACCEPT verdict
 */
static int pisa_handler_i2(hip_fw_context_t *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_I2\n");
	hip_perf_start_benchmark(perf_set, PERF_I2);
#endif
	pisa_insert_puzzle(ctx);

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_I2\n");
	hip_perf_stop_benchmark(perf_set, PERF_I2);
	hip_perf_write_benchmark(perf_set, PERF_I2);
#endif

	return NF_ACCEPT;
}

/**
 * Check for a PISA puzzle, a valid signature and a valid
 * certificate in the R2 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_r2(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0, cert = 0;
	struct hip_challenge_response *solution = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_R2\n");
	hip_perf_start_benchmark(perf_set, PERF_R2);
#endif

	solution = pisa_check_challenge_response(ctx);
	// Done in conntrack.c
	//sig = pisa_check_signature(ctx);
	cert = pisa_check_certificate(ctx);

	if (solution == NULL || sig != 0 || cert != 0) {
		/* disallow further communication if either nonce, solution,
		 * signature or certificate were not correct */
		pisa_reject_connection(ctx);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection(ctx);
		verdict = NF_ACCEPT;
	}

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_R2, PERF_BASE\n");
	hip_perf_stop_benchmark(perf_set, PERF_R2);
	hip_perf_stop_benchmark(perf_set, PERF_BASE);
	hip_perf_write_benchmark(perf_set, PERF_R2);
	hip_perf_write_benchmark(perf_set, PERF_BASE);
#endif

	return verdict;
}

/**
 * Insert a PISA nonce and a PISA puzzle into the U1 packet.
 *
 * @param ctx context of the packet to modify
 * @return NF_ACCEPT verdict
 */
static int pisa_handler_u1(hip_fw_context_t *ctx)
{
	pisa_insert_puzzle(ctx);

	return NF_ACCEPT;
}

/**
 * Check for a PISA nonce, a PISA puzzle, a valid signature and a valid
 * certificate in the U2 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u2(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0, cert = 0;
	struct hip_challenge_response *solution = NULL;

	solution = pisa_check_challenge_response(ctx);
	// Done in conntrack.c
	//sig = pisa_check_signature(ctx);
	cert = pisa_check_certificate(ctx);

	if (solution == NULL || sig != 0 || cert != 0) {
		HIP_DEBUG("U2 packet did not match criteria:  "
			  "solution %p, signature %i, cert %i\n",
			  solution, sig, cert);
		verdict = NF_DROP;
	} else {
		/* packet was ok, insert another puzzle */
		pisa_insert_puzzle(ctx);
		verdict = NF_ACCEPT;
	}

	return verdict;
}

/**
 * Check for a PISA nonce and a valid signature in the U3 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u3(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0, cert = 0;
	struct hip_challenge_response *solution = NULL;

	solution = pisa_check_challenge_response(ctx);
	// Done in conntrack.c
	//sig = pisa_check_signature(ctx);

	if (solution == NULL || sig != 0 ) {
		HIP_DEBUG("U2 packet did not match criteria:  "
					  "solution %p, signature %i, cert %i\n",
					  solution, sig, cert);
		pisa_reject_connection(ctx);
		verdict = NF_DROP;
	} else {

		pisa_accept_connection(ctx);
		verdict = NF_ACCEPT;
	}
	return verdict;
}

/**
 * Handle CLOSE_ACK packet. Remove the connection from the list of accepted
 * connections
 *
 * @param ctx context of the packet
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_close_ack(hip_fw_context_t *ctx)
{
	pisa_remove_connection(ctx);
	return NF_ACCEPT;
}

void pisa_init(struct midauth_handlers *h)
{
	char hit[INET6_ADDRSTRLEN];
	h->i1 = pisa_handler_i1;
	h->r1 = pisa_handler_r1;
	h->i2 = pisa_handler_i2;
	h->r2 = pisa_handler_r2;
	h->u1 = pisa_handler_u1;
	h->u2 = pisa_handler_u2;
	h->u3 = pisa_handler_u3;
	h->close = midauth_handler_accept;
	h->close_ack = pisa_handler_close_ack;

	pisa_generate_random();
	pisa_generate_random();

	if(!pisa_read_communit_operator_hit(hit))
	{
		hit[0]='\0';
		HIP_ERROR("Could not load Communit-Operator HIT from file %s\n",
				CO_HIT_FILE);
	}

	if(inet_pton(AF_INET6, hit, &community_operator_hit)<=0)
	{
		HIP_ERROR("Coult not parse Community-Operator HIT\n");
	}
}
