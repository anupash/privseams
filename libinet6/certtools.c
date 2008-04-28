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
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "certtools.h"
#include "debug.h"
#include "ife.h"

/*******************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                 *
 *******************************************************************************/

/**  
 * Function to build the create minimal SPKI cert  
 * @param minimal_content holds the struct hip_cert_spki_header containing 
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
int hip_cert_spki_create_cert(struct hip_cert_spki_header * minimal_content,
                              char * issuer_type, char * issuer,
                              char * subject_type, char * subject,
                              struct timeval * not_before,
                              struct timeval * not_after) {
	int err = 0;
        char * tmp_issuer;
        char * tmp_subject;

        tmp_issuer = malloc(128);
        if (!tmp_issuer) goto out_err;
        tmp_subject = malloc(128);
        if (!tmp_subject) goto out_err;
        HIP_IFEL(!memset(tmp_issuer, '\0', sizeof(tmp_issuer)), -1,
                 "failed to memset memory for tmp variables\n");
        HIP_IFEL(!memset(tmp_subject, '\0', sizeof(tmp_subject)), -1,
                 "failed to memset memory for tmp variables\n");
        sprintf(tmp_issuer, "(hash %s %s)", issuer_type, issuer);
        sprintf(tmp_subject, "(hash %s %s)", subject_type, subject);

        HIP_IFEL(hip_cert_spki_build_cert(minimal_content), -1, 
                 "hip_cert_spki_build_cert failed\n");

        HIP_IFEL(hip_cert_spki_inject(minimal_content, "cert", "(subject )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        HIP_IFEL(hip_cert_spki_inject(minimal_content, "subject", tmp_subject), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        HIP_IFEL(hip_cert_spki_inject(minimal_content, "cert", "(issuer )"), -1, 
                 "hip_cert_spki_inject failed to inject\n");

        HIP_IFEL(hip_cert_spki_inject(minimal_content, "issuer", tmp_issuer), -1, 
                 "hip_cert_spki_inject failed to inject\n");

out_err:
        free(tmp_issuer);
        free(tmp_subject);
	return (err);
} 
 
/**
 * Function to build the basic cert object of SPKI
 * @param minimal_content holds the struct hip_cert_spki_header containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_header * minimal_content) {
	int err = 0;
	char needed[] = "(cert )";
	memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
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
 * @param to hip_cert_spki_header containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to 
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 *
 * @note Remember to inject in order last first first last, its easier
 */
int hip_cert_spki_inject(struct hip_cert_spki_header * to, 
                         char * after, char * what) {
	int err = 0, status = 0;
        regex_t re;
        regmatch_t pm[1];
        char * tmp_cert;        

        _HIP_DEBUG("Before inject:\n%s\n",to->cert);
        HIP_DEBUG("Inserting \"%s\" after \"%s\"\n", what, after);       
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
