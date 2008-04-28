/** @file
 * A teststub for certtools.c/h
 *
 * File for testing the main operations of certtools.
 * First this test takes the default HIT and the corresponding key.
 * Secondly it creates a certificate where itself is the issuer and the subject.
 * Then it tries to verify it. If it succeeds everything should be OK :)
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */
#include <sys/time.h>
#include <time.h>
#include "ife.h"
#include "debug.h"
#include "certtools.h"

int main(int argc, char *argv[])
{
        int err = 0;
        struct hip_cert_spki_header * cert;
        struct timeval not_before;
        struct timeval not_after;

        HIP_DEBUG("Starting to test SPKI certficate tools\n");
        
        cert = malloc(sizeof(struct hip_cert_spki_header));
        if (!cert) goto out_err;
        
        memset(&not_before, 0, sizeof(struct timeval));
        memset(&not_after, 0, sizeof(struct timeval));

        gettimeofday(&not_before, NULL);
        gettimeofday(&not_after, NULL);

        hip_cert_spki_create_cert(cert, 
                                  "hit", "2001:0011",
                                  "hit", "2001:0012",
                                  &not_before,
                                  &not_after);

        HIP_DEBUG("Certificate contents after create cert:\n"
                  "%s\n", cert->cert);

        HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");
        free(cert);
        exit(EXIT_SUCCESS);

 out_err:
        HIP_DEBUG("Something failed, see above\n");
        free(cert);
        exit(-1);
}
