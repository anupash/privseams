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
#include "ife.h"
#include "debug.h"
#include "certtools.h"

int main(int argc, char *argv[])
{
        int err = 0;
        struct hip_cert_spki_header * cert;

        HIP_DEBUG("Starting to test SPKI certficate tools\n");
        
        cert = malloc(sizeof(struct hip_cert_spki_header));
        if (!cert) goto out_err;
        
        //building the outermost sequence
        HIP_IFEL(hip_cert_spki_build_cert(cert), -1, 
                 "hip_cert_spki_build_cert failed\n");
        
        HIP_DEBUG("Certificate contents:\n"
                  "%s\n"
                  "First inject\n", cert->cert);
        
        HIP_IFEL(hip_cert_spki_inject(cert, "rt", "injected"), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");
        exit(EXIT_SUCCESS);

 out_err:
        HIP_DEBUG("Something failed, see above\n");
        exit(-1);
}
