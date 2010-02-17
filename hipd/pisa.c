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
static int hip_pisa_load_certificate(void)
{
    FILE *f = NULL;

    if (midauth_cert) {
        free(midauth_cert);
    }
    midauth_cert = malloc(CERT_MAX_SIZE);
    memset(midauth_cert, 0, CERT_MAX_SIZE);

    if (!(f = fopen("/etc/hip/cert", "r"))) {
        HIP_ERROR("Could not open certificate file.\n");
        return -1;
    }

    if (fread(midauth_cert, CERT_MAX_SIZE - 1, 1, f) == 0) {
        perror("fread returned 0");
    }
    fclose(f);
    return 0;
}

char *hip_pisa_get_certificate(void)
{
    hip_pisa_load_certificate();
    return midauth_cert;
}
