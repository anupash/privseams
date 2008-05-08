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
#include "icomm.h"
#include "debug.h"
#include "certtools.h"

int main(int argc, char *argv[])
{
        int err = 0;
        struct hip_cert_spki_info * cert;
        time_t not_before = 0, not_after = 0;
        struct hip_common *msg;
        struct in6_addr *defhit;
        struct hip_tlv_common *current_param = NULL;
        struct endpoint_hip *endp = NULL;

        HIP_DEBUG("Starting to test SPKI certficate tools\n");
        HIP_DEBUG("Hipd has to run otherwise this will hang\n");
        
        cert = malloc(sizeof(struct hip_cert_spki_info));
        if (!cert) goto out_err;

        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");        

        time(&not_before);
        time(&not_after);

        /* get the first RSA HIT */
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HITS,0),-1, "Fail to get hits");
        hip_send_recv_daemon_info(msg);
	
        while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
                endp = (struct endpoint_hip *)
                        hip_get_param_contents_direct(current_param);
                if (endp->algo == HIP_HI_RSA) {
                        defhit = &endp->id.hit;
                        break;
                }
        }
        HIP_DEBUG("Add 3 000 000 seconds to time now (for not_after)\n");
        not_after += 3000000;
        hip_cert_spki_create_cert(cert, 
                                  "hit", defhit,
                                  "hit", defhit,
                                  &not_before,
                                  &not_after);

        HIP_DEBUG("Certificate contents after all is done:\n"
                  "%s\n", cert->cert);

        HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");
        free(cert);
        exit(EXIT_SUCCESS);

 out_err:
        HIP_DEBUG("Something failed, see above\n");
        free(cert);
        exit(-1);
}
