/** @file
 * This file contains PISA specific functions for the firewall. The basic idea
 * is to modify the HIP messages and manage state for allowed connections to
 * allow or reject associated ESP traffic.
 *
 * @author Thomas Jansen
 *
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "ife.h"
#include "midauth.h"
#include "misc.h"
#include "pisa.h"
#include "pisa_cert.h"
#include "hslist.h"
#include <string.h>

#define PISA_RANDOM_LEN 16
#define PISA_PUZZLE_SEED 0xDEADC0DE
#define PISA_NONCE_LEN_1SPI (4 + HIP_AH_SHA_LEN)
#define PISA_NONCE_LEN_2SPI (8 + HIP_AH_SHA_LEN)

#ifdef CONFIG_HIP_PERFORMANCE
#include "performance.h"
#endif

struct pisa_conn {
	uint32_t spi[2];
	struct in6_addr hit[2];
};

static SList *pisa_connections = NULL;

struct pisa_conn_query {
	struct in6_addr *hit[2];
};

static struct pisa_conn *pisa_find_conn(struct pisa_conn
					*(*f)(SList *s, void *p),
					void *data)
{
	SList *l = pisa_connections;
	struct pisa_conn *pcd;

	while (l) {
		pcd = f(l, data);
		if (pcd != NULL)
			return pcd;
		l = l->next;
	}

	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_hits2(SList *s, void *p)
{
	struct pisa_conn_query *query = (struct pisa_conn_query *) p;
	struct pisa_conn *data;

	if (s && s->data) {
		data = (struct pisa_conn *) s->data;
		if ((!ipv6_addr_cmp(&data->hit[0], query->hit[0]) &&
		     !ipv6_addr_cmp(&data->hit[1], query->hit[1])) ||
		    (!ipv6_addr_cmp(&data->hit[0], query->hit[1]) &&
		     !ipv6_addr_cmp(&data->hit[1], query->hit[0])))
			return data;
	}
	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_hits(struct in6_addr *hit1,
						struct in6_addr *hit2)
{
	struct pisa_conn_query data;

	data.hit[0] = hit1;
	data.hit[1] = hit2;

	return pisa_find_conn(pisa_find_conn_by_hits2, &data);
}

static struct pisa_conn *pisa_find_conn_by_spi2(SList *s, void *p)
{
	uint32_t *spi = (uint32_t *) p;
	struct pisa_conn *data;

	if (s && s->data) {
		data = (struct pisa_conn *) s->data;
		if (data->spi[0] == *spi || data->spi[1] == *spi)
			return data;
	}

	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_spi(uint32_t spi)
{
	return pisa_find_conn(pisa_find_conn_by_spi2, &spi);
}

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
	void *p0, *p1;

	p0 = &pisa_random_data[0][0];
	p1 = &pisa_random_data[1][0];

	memcpy(p0, p1, PISA_RANDOM_LEN);
	get_random_bytes(p1, PISA_RANDOM_LEN);

	HIP_DEBUG("updated pisa_random_data.\n");
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
	int len = HIP_AH_SHA_LEN, err = 0;

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
 * Insert a PISA nonce into a packet that will contain 1 SPI.
 *
 * @param ctx context of the packet where the nonce will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_nonce_1spi(hip_fw_context_t *ctx)
{
	u8 nonce[PISA_NONCE_LEN_1SPI];
	struct hip_esp_info *esp_info;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u32 spi = 0;

	esp_info = hip_get_param(hip, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL)
		spi = esp_info->new_spi;

	/* The nonce looks like this:
	 *    4 bytes SPI
	 *   20 bytes HMAC of everything before
	 * As we only use the data in the firewall, byteorder is not an issue.
	 */

	memcpy(nonce, &spi, sizeof(u32));
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, nonce, sizeof(u32));

	return midauth_add_echo_request_m(ctx, nonce, PISA_NONCE_LEN_1SPI);
}

/**
 * Insert a PISA nonce into a packet that will contain 2 SPIs.
 *
 * @param ctx context of the packet where the nonce will be inserted
 * @param old_nonce parameter in ctx that contains the old SPI
 * @return success (0) or failure
 */
static int pisa_insert_nonce_2spi(hip_fw_context_t *ctx,
				  struct hip_tlv_common *old_nonce)
{
	u8 nonce[PISA_NONCE_LEN_2SPI];
	struct hip_esp_info *esp_info;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u32 spi[2] = {0, 0};

	if (old_nonce != NULL)
		spi[0] = *((u32 *)hip_get_param_contents_direct(old_nonce));

	esp_info = hip_get_param(hip, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL)
		spi[1] = esp_info->new_spi;

	/* The nonce looks like this:
	 *    4 bytes first SPI
	 *    4 bytes second SPI
	 *   20 bytes HMAC of everything before
	 * As we only use the data in the firewall, byteorder is not an issue.
	 */

	memcpy(nonce, &spi[0], sizeof(u32));
	memcpy(nonce+sizeof(u32), &spi[1], sizeof(u32));
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, nonce, sizeof(u32)*2);

	return midauth_add_echo_request_m(ctx, nonce, PISA_NONCE_LEN_2SPI);
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

	/* here we switch order of initiator and receiver to obtain a
	 * different SHA1 hash */
	pisa_append_hmac(&hip->hitr, &hip->hits, 1, &hash, 4);

	return midauth_add_puzzle_m(ctx, 3, 4, hash.u.pz.opaque,
	                            hash.u.pz.random);
}

/**
 * Check the validity of a PISA nonce. Check against current random value
 * first. If that fails, check against old random value. If that fails too,
 * consider the nonce to be invalid (either too old or not correct at any
 * previous point in time).
 *
 * @param ctx context of the packet with the nonce to check
 * @return pointer to the nonce we accepted or NULL at failure
 */
static struct hip_tlv_common *pisa_check_nonce(hip_fw_context_t *ctx)
{
	struct hip_tlv_common *nonce;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u8 valid[PISA_NONCE_LEN_2SPI], *nonce_data;
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
		if (nonce_len == PISA_NONCE_LEN_1SPI ||
		    nonce_len == PISA_NONCE_LEN_2SPI) {
			int data_size = sizeof(u32);

			if (nonce_len == PISA_NONCE_LEN_2SPI)
				data_size = sizeof(u32) * 2;

			memcpy(valid, nonce_data, data_size);
			spi = *((u32 *)nonce_data);

			/* ... first check the current random value ... */
			pisa_append_hmac(&hip->hitr, &hip->hits, 1, valid,
					 data_size);
			if (!memcmp(valid, nonce_data, nonce_len))
				return nonce;

			/* ... and if that failed the old random value */
			pisa_append_hmac(&hip->hitr, &hip->hits, 0, valid,
					 data_size);
			if (!memcmp(valid, nonce_data, nonce_len))
				return nonce;
		}

		nonce = hip_get_next_param(hip, nonce);
	}

	return NULL;
}

/**
 * Check the validity of a PISA puzzle.
 *
 * @param ctx context of the packet with the puzzle to check
 * @return pointer to the puzzle we accepted or NULL at failure
 */
static struct hip_solution_m *pisa_check_solution(hip_fw_context_t *ctx)
{
	struct hip_solution_m *solution;
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct pisa_puzzle_hash hash[2];
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash[0], &seed, 4);
	memcpy(&hash[1], &seed, 4);

	pisa_append_hmac(&hip->hits, &hip->hitr, 0, &hash[0], 4);
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, &hash[1], 4);

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
				return solution;
		}

		solution = (struct hip_solution_m *) hip_get_next_param(hip,
				(struct hip_tlv_common *) solution);
	}

	return NULL;
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
		if (hip_get_host_id_algo(host_id) == HIP_HI_RSA)
			verify_signature = hip_rsa_verify;
		else
			verify_signature = hip_dsa_verify;

		err = verify_signature(host_id, hip);
	}

out_err:
	return err;
}

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
		 "Signature could not be verified.\n");

	HIP_DEBUG("Verified signature. Seems to be valid.\n");

	pisa_split_cert(ci.cert, &pc);

	HIP_DEBUG("split cert contains data: %i, %i\n", pc.not_before, pc.not_after);
	HIP_DEBUG_HIT("issuer_hit", &pc.hit_issuer);
	HIP_DEBUG_HIT("subject_hit", &pc.hit_subject);

	HIP_IFEL(now < pc.not_before, -1,
		 "Certificate violates the not before condition.\n");
	HIP_IFEL(now > pc.not_after, -1,
		 "Certificate violates the not after condition.\n");

out_err:
	if (buf)
		free(buf);
	return err;
}

/**
 * Accept a connection via PISA. Update firewall to allow further packages to
 * pass through.
 *
 * @param hits HIT of the sender
 * @param spi_s SPI of the sender
 * @param hitr HIT of the receiver
 * @param spi_r SPI of the receiver
 */
static void pisa_accept_connection(struct in6_addr *hits, uint32_t spi_s,
				   struct in6_addr *hitr, uint32_t spi_r)
{
	struct tuple *t = get_tuple_by_hits(hits, hitr);

	if (t) {
		t->connection->pisa_state = PISA_STATE_ALLOW;
		HIP_INFO("PISA accepted the connection.\n");
	} else {
		HIP_ERROR("Connection not found.\n");
	}
}

/**
 * Accept a connection via PISA after receiving an I2 packet.
 *
 * @param ctx context of the packet that belongs to that connection
 * @param nonce the nonce we accepted
 */
static void pisa_accept_connection_i2(hip_fw_context_t *ctx,
				      struct hip_tlv_common *nonce)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct hip_esp_info *esp;
	uint32_t *spi;

	if (nonce == NULL) {
		HIP_DEBUG("Accepting failed: no nonce found.\n");
		return;
	}

	esp = hip_get_param(hip, HIP_PARAM_ESP_INFO);

	if (esp == NULL) {
		HIP_DEBUG("Accepting failed: no HIP_PARAM_ESP_INFO found.\n");
		return;
	}

	spi = (uint32_t *) hip_get_param_contents_direct(nonce);

	pisa_accept_connection(&hip->hits, esp->new_spi, &hip->hitr, *spi);
}

/**
 * Accept a connection via PISA after receiving an U3 packet.
 *
 * @param ctx context of the packet that belongs to that connection
 * @param nonce the nonce we accepted
 */
static void pisa_accept_connection_u3(hip_fw_context_t *ctx,
				      struct hip_tlv_common *nonce)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	uint32_t spi[2], *p;

	if (nonce == NULL) {
		HIP_DEBUG("Accepting failed: no nonce found.\n");
		return;
	}

	p = (uint32_t *) hip_get_param_contents_direct(nonce);
	spi[0] = *(p);
	spi[1] = *(p + 1);

	pisa_accept_connection(&hip->hits, spi[0], &hip->hitr, spi[1]);
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
static void pisa_reject_connection(hip_fw_context_t *ctx,
				   struct hip_tlv_common *nonce)
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
 * Insert a PISA nonce and a PISA puzzle into the I2 packet.
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

	pisa_insert_nonce_1spi(ctx);
	pisa_insert_puzzle(ctx);

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_I2\n");
	hip_perf_stop_benchmark(perf_set, PERF_I2);
	hip_perf_write_benchmark(perf_set, PERF_I2);
#endif

	return NF_ACCEPT;
}

/**
 * Check for a PISA nonce, a PISA puzzle, a valid signature and a valid
 * certificate in the R2 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_r2(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0, cert = 0;
	struct hip_solution_m *solution = NULL;
	struct hip_tlv_common *nonce = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_R2\n");
	hip_perf_start_benchmark(perf_set, PERF_R2);
#endif

	nonce = pisa_check_nonce(ctx);
	solution = pisa_check_solution(ctx);
	sig = pisa_check_signature(ctx);
	cert = pisa_check_certificate(ctx);

	if (nonce == NULL || solution == NULL || sig != 0 || cert != 0) {
		/* disallow further communication if either nonce, solution,
		 * signature or certificate were not correct */
		pisa_reject_connection(ctx, nonce);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection_i2(ctx, nonce);
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
	pisa_insert_nonce_1spi(ctx);
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
	struct hip_solution_m *solution = NULL;
	struct hip_tlv_common *nonce = NULL;

	nonce = pisa_check_nonce(ctx);
	solution = pisa_check_solution(ctx);
	sig = pisa_check_signature(ctx);
	cert = pisa_check_certificate(ctx);

	if (nonce == NULL || solution == NULL || sig != 0 || cert != 0) {
		HIP_DEBUG("U2 packet did not match criteria: nonce %p, "
			  "solution %p, signature %i, cert %i\n", nonce,
			  solution, sig, cert);
		verdict = NF_DROP;
	} else {
		/* packet was ok, forward the first SPI */
		pisa_insert_nonce_2spi(ctx, nonce);
		verdict = NF_ACCEPT;
	}

	return verdict;
}

/**
 * Check for a PISA nonce in the U3 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u3(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0;
	struct hip_tlv_common *nonce = NULL;

	nonce = pisa_check_nonce(ctx);
	sig = pisa_check_signature(ctx);

	if (nonce == NULL || sig != 0) {
		HIP_DEBUG("U3 packet did not match criteria: nonce %p, "
			  "signature %i\n", nonce, sig);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection_u3(ctx, nonce);
		verdict = NF_ACCEPT;
	}

	return verdict;
}

/**
 * Handle ESP data that should be forwarded.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_esp(hip_fw_context_t *ctx)
{
	int err = NF_DROP;
	struct hip_esp *esp;
	struct pisa_conn *pcd;

	esp = ctx->transport_hdr.esp;
	HIP_IFEL(esp == NULL, NF_DROP, "No ESP Header found.\n");
	
	pcd = pisa_find_conn_by_spi(esp->esp_spi);
	HIP_IFEL(pcd == NULL, NF_DROP, "Connection not found.\n");

	err = NF_ACCEPT;
	HIP_DEBUG("Connection found, forwarding ESP packet.\n");
out_err:
	return err;
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
	h->i1 = pisa_handler_i1;
	h->r1 = pisa_handler_r1;
	h->i2 = pisa_handler_i2;
	h->r2 = pisa_handler_r2;
	h->u1 = pisa_handler_u1;
	h->u2 = pisa_handler_u2;
	h->u3 = pisa_handler_u3;
	h->esp = pisa_handler_esp;
	h->close = midauth_handler_accept;
	h->close_ack = pisa_handler_close_ack;

	pisa_generate_random();
	pisa_generate_random();

	pisa_connections = alloc_slist();
}

#endif

