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
        struct hip_cert_spki_info * to_verification;
        time_t not_before = 0, not_after = 0;
        struct hip_common *msg;
        struct in6_addr *defhit;
        struct hip_tlv_common *current_param = NULL;
        struct endpoint_hip *endp = NULL;
        char temporary[256];
       
        HIP_DEBUG("Starting to test SPKI certficate tools\n");
        HIP_DEBUG("Hipd has to run otherwise this will hang\n");
        
        cert = malloc(sizeof(struct hip_cert_spki_info));
        if (!cert) goto out_err;
        
        to_verification = malloc(sizeof(struct hip_cert_spki_info));
        if (!to_verification) goto out_err;

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

        _HIP_DEBUG("\n\nPublic-key sequence contents after all is done:\n\n"
                  "%s\n\n", cert->public_key);
        
        _HIP_DEBUG("Cert sequence contents after all is done:\n\n"
                  "%s\n\n", cert->cert);
           
        _HIP_DEBUG("Signature sequence contents after all is done:\n\n"
                  "%s\n\n", cert->signature);
        /* 
           Concatenate everything together as if we would have gotten 
           it from someone else and we would be starting to verify. 

           So the process would be take the cert blob and take out
           public-key sequence, cert sequence and signature sequence
           and create a hip_cert_spki_info and send it to the daemon 
           for verification.
        */
        memset(&temporary, '\0', sizeof(temporary));
        sprintf(&temporary,"(sequence %s%s%s)", 
                cert->public_key, cert->cert, cert->signature);
        HIP_DEBUG("\n\nCertificate gotten back from daemon:\n\n"
                  "%s\n\nCertificate len %d\n\n",
                  temporary, strlen(temporary));

        HIP_IFEL(hip_cert_spki_char2certinfo(temporary, to_verification), -1,
                 "Failed to construct the hip_cert_spki_info from certificate\n");

        /* Send the cert to the daemon for verification */
        HIP_DEBUG("Sending the certificate to daemon for verification\n");

        HIP_IFEL(hip_cert_send_to_verification(to_verification), -1,
                 "Failed in sending to verification\n");
        HIP_IFEL(to_verification->success, -1, 
                 "Verification was not successfull\n");
        HIP_DEBUG("Verification was successfull (return value %d)\n", 
                  to_verification->success);

        HIP_DEBUG("If there was no errors above, \"everything\" is OK\n");

 out_err:
        if (cert) free(cert);
        if (to_verification) free(to_verification);
        exit(err);
}

