/** @file
 * This file contains functions that are specific to PISA. They deal with the
 * certificate loading.
 *
 * @author Thomas Jansen
 */

#include "hipd.h"

#define CERT_MAX_SIZE 1024

static char *midauth_cert = NULL;

/**
 * Load a certificate from the file /etc/hip/cert and store it in memory
 *
 * @return 0 on success
 */
int hip_pisa_load_certificate(void)
{
	int err = 0;
	FILE *f = NULL;

	if (midauth_cert)
		free(midauth_cert);
	midauth_cert = malloc(CERT_MAX_SIZE);
	memset(midauth_cert, 0, CERT_MAX_SIZE);

	if (!(f = fopen("/etc/hip/cert", "r"))) {
		HIP_ERROR("Could not open certificate file.\n");
		return -1;
	}

	fread(midauth_cert, CERT_MAX_SIZE - 1, 1, f);
	fclose(f);
	return 0;
}

char *hip_pisa_get_certificate(void)
{
	/* @todo Buffering a certificate without reloading it after a while
	 * might cause trouble if the daemon is running for a long time */
	if (!midauth_cert)
		hip_pisa_load_certificate();
	return midauth_cert;
}
