/** @file
 * This file defines the certificate building and verification functions to use with HIP
 *
 * Syntax in the names of functions is as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *   VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */
#include "certtools.h"

/*******************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                 *
 *******************************************************************************/

/**  
 * Function to build the create minimal SPKI cert  
 * @param minimal_content holds the struct hip_cert_spki_info containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 * @param issuer_type With HIP its HIT
 * @param issuer HIT in representation encoding 2001:001...
 * @param subject_type With HIP its HIT
 * @param subject HIT in representation encoding 2001:001...
 * @param not_before time in timeval before which the cert should not be used
 * @param not_after time in timeval after which the cert should not be used
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_create_cert(struct hip_cert_spki_info * content,
                              char * issuer_type, struct in6_addr * issuer,
                              char * subject_type, struct in6_addr * subject,
                              time_t * not_before, time_t * not_after) {
	int err = 0;
        char * tmp_issuer;
        char * tmp_subject;
        char * tmp_before;
        char * tmp_after;
        struct tm *ts;
        char buf_before[80];
        char buf_after[80];
        char present_issuer[41];
        char present_subject[41];
        struct hip_common *msg;

        /* Malloc needed */

        tmp_issuer = malloc(128);
        if (!tmp_issuer) goto out_err;
        tmp_subject = malloc(128);
        if (!tmp_subject) goto out_err;
        tmp_before = malloc(128);
        if (!tmp_before) goto out_err;
        tmp_after = malloc(128);
        if (!tmp_after) goto out_err;
        HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, 
                 "Malloc for msg failed\n");   

        /* Memset everything */

        HIP_IFEL(!memset(buf_before, '\0', sizeof(buf_before)), -1,
                 "failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(buf_after, '\0', sizeof(buf_after)), -1,
                 "failed to memset memory for tmp buffers variables\n");
        HIP_IFEL(!memset(tmp_issuer, '\0', sizeof(tmp_issuer)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_subject, '\0', sizeof(tmp_subject)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_before, '\0', sizeof(tmp_before)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_after, '\0', sizeof(tmp_after)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_issuer, '\0', sizeof(present_issuer)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(present_subject, '\0', sizeof(present_subject)), -1,
                 "failed to memset memory for tmp variables\n");

        /* Make needed transforms to the date

        _HIP_DEBUG("not_before %d not_after %d\n",*not_before,*not_after);
        /*  Format and print the time, "yyyy-mm-dd hh:mm:ss"
           (not-after "1998-04-15_00:00:00") */
        ts = localtime(not_before);
        strftime(buf_before, sizeof(buf_before), "%Y-%m-%d_%H:%M:%S", ts);
        ts = localtime(not_after);
        strftime(buf_after, sizeof(buf_after), "%Y-%m-%d_%H:%M:%S", ts);
        _HIP_DEBUG("Not before %s\n", buf_before);
        _HIP_DEBUG("Not after %s\n", buf_after);

        sprintf(tmp_before, "(not-before \"%s\")", buf_before);
        sprintf(tmp_after, "(not-after \"%s\")", buf_after);
        
        ipv6_addr_copy(&content->issuer_hit, issuer);
        hip_in6_ntop(issuer, present_issuer);        
        hip_in6_ntop(subject, present_subject);

        sprintf(tmp_issuer, "(hash %s %s)", issuer_type, present_issuer);
        sprintf(tmp_subject, "(hash %s %s)", subject_type, present_subject);

        /* Create the cert sequence */        

        HIP_IFEL(hip_cert_spki_build_cert(content), -1, 
                 "hip_cert_spki_build_cert failed\n");

        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_after), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", tmp_before), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(subject )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "subject", tmp_subject), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "cert", "(issuer )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");
        HIP_IFEL(hip_cert_spki_inject(content, "issuer", tmp_issuer), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        /* Create the signature and the public-key sequences */
        
        /* Send the daemon the struct hip_cert_spki_header 
           containing the cert sequence in content->cert. 
           As a result you should get the struct back with 
           public-key and signature fields filled */

        /* build the msg to be sent to the daemon */
        HIP_IFEL(hip_build_param_cert_spki_info(msg, content), -1,
                 "Failed to build cert_info\n");         
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI, 0), -1, 
                 "Failed to build user header\n");
        /* send and wait */
        HIP_DEBUG("Sending request to sign SPKI cert sequence to "
                  "daemon and waiting for answer\n");
        hip_send_recv_daemon_info(msg);
        
        /* get the struct from the messag hip_db_struct_t;e */

out_err:
        /* free everything malloced */
        free(tmp_before);
        free(tmp_after);
        free(tmp_issuer);
        free(tmp_subject);
        free(msg);
	return (err);
} 
 
/**
 * Function to build the basic cert object of SPKI clears public-key object
 * and signature in hip_cert_spki_header
 * @param minimal_content holds the struct hip_cert_spki_header containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_info * minimal_content) {
	int err = 0;
	char needed[] = "(cert )";
	memset(minimal_content->public_key, '\0', sizeof(minimal_content->public_key));
	memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
	memset(minimal_content->signature, '\0', sizeof(minimal_content->signature));
        sprintf(minimal_content->cert, "%s", needed);

out_err:
	return (err);
}

/**
 * Function to build the signature object for SPKI also builds 
 * the public key object and the surrounding sequence object
 *
 * @param key RSA struct containing the public key to be used in signature process
 * @param in char table containing the cert object to be signed
 * @param out char table where the resulting certificate will be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_signature(char * in, char * out) {
	int err = 0;

out_err:
	return (err);
}

/**
 * Function for injecting objects to cert object
 *
 * @param to hip_cert_spki_info containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to 
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 *
 * @note Remember to inject in order last first first last, its easier
 */
int hip_cert_spki_inject(struct hip_cert_spki_info * to, 
                         char * after, char * what) {
	int err = 0, status = 0;
        regex_t re;
        regmatch_t pm[1];
        char * tmp_cert;        

        _HIP_DEBUG("Before inject:\n%s\n",to->cert);
        _HIP_DEBUG("Inserting \"%s\" after \"%s\"\n", what, after);       
        tmp_cert = malloc(strlen(to->cert) + strlen(what) + 1);
        if (!tmp_cert) return(-1);
        HIP_IFEL(!memset(tmp_cert, 0, sizeof(tmp_cert)), -1,
                 "Failed to memset temporary workspace\n");        
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, after, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, to->cert, 1, pm, 0)), -1,
                 "Handling of regular expression failed\n");
        _HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  after, pm[0].rm_so, pm[0].rm_eo);
        /* Using tmp char table to do the inject (remember the terminators)
           first the beginning */
        snprintf(tmp_cert, pm[0].rm_eo + 2, "%s", to->cert);
        /* Then the middle part to be injected */
        snprintf(&tmp_cert[pm[0].rm_eo + 1], strlen(what) + 1, "%s", what);
        /* then glue back the rest of the original at the end */
        snprintf(&tmp_cert[(pm[0].rm_eo + strlen(what) + 1)], 
                (strlen(to->cert) - pm[0].rm_eo), "%s", &to->cert[pm[0].rm_eo + 1]);
        /* move tmp to the result */
        sprintf(to->cert, "%s", tmp_cert);
        _HIP_DEBUG("After inject:\n%s\n",to->cert);
out_err:
        free(tmp_cert);
	return (err);
}

/*******************************************************************************
 * VERIFICATION FUNCTIONS FOR SPKI                                             *
 *******************************************************************************/

/**
 * Function that verifies the signature in the SPKI certificate
 *
 * @param in char table containing the certificate to be verified
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_verify_signature(char * in) {
	int err = 0;
	
out_err:
	return (err);
}
